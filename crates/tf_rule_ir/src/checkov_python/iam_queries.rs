use super::*;

/// policy_sentry's and cloudsplaining's IAM-database queries, ported
/// exactly over [`iam::definition`] (see `NATIVE` in the importer).
impl Interp<'_> {
    #[expect(clippy::too_many_lines)]
    pub(super) fn iam_builtin(
        &mut self,
        name: &str,
        args: Vec<Py>,
        kwargs: Vec<(String, Py)>,
    ) -> R<Py> {
        let arg = |i: usize, kw: &str| Self::arg(&args, &kwargs, i, kw);
        let text = |this: &Self, v: Option<Py>| -> R<Rc<str>> {
            match v.map(|v| this.concrete(&v)).transpose()? {
                Some(Py::Str(s)) => Ok(s),
                _ => exc("TypeError"),
            }
        };
        Ok(match name {
            "iam.get_all_service_prefixes" => Py::Set(Rc::new(RefCell::new(
                iam::prefixes().map(Py::str).collect(),
            ))),
            "iam.get_all_actions" => {
                let lower = match arg(0, "lowercase") {
                    Some(v) => self.truthy(&v)?,
                    None => false,
                };
                Py::Set(Rc::new(RefCell::new(
                    iam::all_actions(lower)
                        .into_iter()
                        .map(|a| Py::str(&a))
                        .collect(),
                )))
            }
            "iam.get_actions_for_service" => {
                let prefix = text(self, arg(0, "service_prefix"))?;
                let lower = match arg(1, "lowercase") {
                    Some(v) => self.truthy(&v)?,
                    None => false,
                };
                Py::list(
                    iam::actions_for_service(&prefix, lower)
                        .into_iter()
                        .map(|a| Py::str(&a))
                        .collect(),
                )
            }
            "iam.get_action_data" => {
                let service = text(self, arg(0, "service"))?;
                let action = text(self, arg(1, "action_name"))?;
                self.action_data(&service, &action)?
            }
            "iam.remove_actions_not_matching_access_level" => {
                let list = arg(0, "actions_list").ok_or_else(type_error)?;
                let (actions, star) = (self.iterate(&list)?, self.is_star_list(&list)?);
                let level = text(self, arg(1, "access_level"))?;
                Py::list(self.matching_level(&actions, star, &level)?)
            }
            "iam.remove_read_level_actions" => {
                let list = arg(0, "actions_list").ok_or_else(type_error)?;
                let (actions, star) = (self.iterate(&list)?, self.is_star_list(&list)?);
                let mut out = Vec::new();
                for level in ["Write", "Permissions management", "Tagging"] {
                    out.extend(self.matching_level(&actions, star, level)?);
                }
                Py::list(out)
            }
            "iam.expand" => {
                let action = arg(0, "action").ok_or_else(type_error)?;
                Py::list(self.expand(&action)?)
            }
            "iam.determine_actions_to_expand" => {
                let actions = self.iterate(&arg(0, "action_list").ok_or_else(type_error)?)?;
                let mut out: Vec<Py> = Vec::new();
                for a in actions {
                    match self.concrete(&a)? {
                        Py::Str(s) if s.contains('*') => out.extend(self.expand(&Py::Str(s))?),
                        Py::Str(s) => out.push(Py::Str(s)),
                        _ => return exc("TypeError"),
                    }
                }
                let list = Py::list(out);
                self.method(list.clone(), "sort", Vec::new(), Vec::new())?;
                list
            }
            "iam.remove_wildcard_only_actions" => {
                let actions = self.iterate(&arg(0, "actions_list").ok_or_else(type_error)?)?;
                let unique = self.dedup(actions)?;
                let prefixes: std::collections::HashSet<&str> = iam::prefixes().collect();
                let mut out = Vec::new();
                for a in unique {
                    let Py::Str(a) = self.concrete(&a)? else {
                        return exc("AttributeError");
                    };
                    let parts: Vec<&str> = a.split(':').collect();
                    let [prefix, action] = parts[..] else {
                        return exc("ValueError");
                    };
                    if !prefixes.contains(prefix) {
                        continue;
                    }
                    let Some(service) = iam::service(prefix) else {
                        continue;
                    };
                    let Some(name) = iam::action_name(service, action) else {
                        continue;
                    };
                    let types = service["privileges"][name]["resource_types"]
                        .as_object()
                        .map_or(0, |m| m.len());
                    let first_arn = iam::entries(service, name).into_iter().next();
                    match (types, first_arn) {
                        (0, _) | (_, None) => {}
                        (1, Some(arn)) if arn == "*" => {}
                        _ => out.push(Py::str(&format!(
                            "{}:{name}",
                            service["prefix"].as_str().unwrap_or(prefix)
                        ))),
                    }
                }
                Py::list(out)
            }
            other => return unsupported(format!("builtin {other}")),
        })
    }

    /// `get_action_data(service, action_name)`.
    pub(super) fn action_data(&self, service: &str, action: &str) -> R<Py> {
        // get_service_prefix_data returns {} for an unknown service; the
        // lookup that follows raises KeyError.
        let Some(sd) = iam::service(service) else {
            return exc("KeyError");
        };
        let names: Vec<&str> = if action == "*" {
            sd["privileges"]
                .as_object()
                .map_or(Vec::new(), |m| m.keys().map(String::as_str).collect())
        } else {
            match iam::action_name(sd, action) {
                Some(n) => vec![n],
                None => return Ok(Py::Dict(Rc::new(RefCell::new(Vec::new())))),
            }
        };
        let mut results = Vec::new();
        for name in names {
            results.extend(self.action_entries(sd, name));
        }
        Ok(Py::Dict(Rc::new(RefCell::new(vec![(
            Py::str(service),
            Py::list(results),
        )]))))
    }

    /// `create_action_data_entries`: one entry per resource type, all
    /// sharing one `dependent_actions` list, as in policy_sentry.
    pub(super) fn action_entries(&self, sd: &'static Json, name: &str) -> Vec<Py> {
        let privilege = &sd["privileges"][name];
        let dependent: List = Rc::new(RefCell::new(Vec::new()));
        let mut out = Vec::new();
        let empty = serde_json::Map::new();
        for (rt, entry) in privilege["resource_types"].as_object().unwrap_or(&empty) {
            if let Some(deps) = entry["dependent_actions"].as_array() {
                dependent.borrow_mut().extend(deps.iter().map(json_to_py));
            }
            let arn = iam::arn_format(sd, rt);
            let pairs = vec![
                (
                    Py::str("action"),
                    Py::str(&format!("{}:{name}", sd["prefix"].as_str().unwrap_or(""))),
                ),
                (Py::str("description"), Py::str("")),
                (
                    Py::str("access_level"),
                    json_to_py(&privilege["access_level"]),
                ),
                (Py::str("api_documentation_link"), Py::str("")),
                (Py::str("resource_arn_format"), Py::str(arn)),
                (Py::str("condition_keys"), Py::list(Vec::new())),
                (Py::str("dependent_actions"), Py::List(dependent.clone())),
            ];
            out.push(Py::Dict(Rc::new(RefCell::new(pairs))));
        }
        out
    }

    /// `actions_list == ["*"]`: a list (no other iterable) of just `"*"`.
    pub(super) fn is_star_list(&self, v: &Py) -> R<bool> {
        let Py::List(l) = self.concrete(v)? else {
            return Ok(false);
        };
        let items = l.borrow().clone();
        Ok(items.len() == 1 && self.eq(&items[0], &Py::str("*"))?)
    }

    /// `remove_actions_not_matching_access_level`; `star` is whether the
    /// argument was the list `["*"]`, which stands for every action.
    pub(super) fn matching_level(&self, actions: &[Py], star: bool, level: &str) -> R<Vec<Py>> {
        let mut actions = actions.to_vec();
        if star {
            actions = Vec::new();
            for prefix in iam::prefixes() {
                let Some(sd) = iam::service(prefix) else {
                    continue;
                };
                for (name, p) in sd["privileges"].as_object().into_iter().flatten() {
                    if p["access_level"] == level {
                        actions.push(Py::str(&format!("{prefix}:{name}")));
                    }
                }
            }
        }
        let mut out = Vec::new();
        for a in actions {
            let Py::Str(a) = self.concrete(&a)? else {
                return exc("AttributeError");
            };
            let parts: Vec<&str> = a.split(':').collect();
            let [prefix, action] = parts[..] else {
                continue; // ValueError on unpacking: skipped
            };
            let Some(sd) = iam::service(&prefix.to_lowercase()) else {
                continue;
            };
            if let Some(name) = iam::action_name(sd, action)
                && sd["privileges"][name]["access_level"] == level
            {
                out.push(Py::str(&format!("{prefix}:{name}")));
            }
        }
        Ok(out)
    }

    /// `expand(action)`.
    pub(super) fn expand(&self, action: &Py) -> R<Vec<Py>> {
        let action = match self.concrete(action)? {
            Py::List(l) => {
                let items = l.borrow().clone();
                let mut out = Vec::new();
                for i in items {
                    out.extend(self.expand(&i)?);
                }
                return Ok(out);
            }
            Py::Str(s) => s,
            _ => return exc("TypeError"),
        };
        if !action.contains('*') {
            return Ok(vec![Py::Str(action)]);
        }
        // A pure function of the bundled database: each wildcard is
        // expanded once per thread, however many checks and resources ask.
        thread_local! {
            static EXPANDED: RefCell<Expansions> = RefCell::new(HashMap::default());
        }
        if let Some(hit) = EXPANDED.with(|m| m.borrow().get(&action).cloned()) {
            return Ok(hit.iter().map(|a| Py::Str(a.clone())).collect());
        }
        let expanded: Vec<Rc<str>> = if &*action == "*" {
            iam::all_actions(false)
                .into_iter()
                .map(|a| Rc::from(a.as_str()))
                .collect()
        } else {
            // fnmatchcase(f"{prefix}:{name}".lower(), action.lower()), with
            // the prefix (which names a service) matched literally.
            let prefix = action.split(':').next().unwrap_or("");
            let pattern = action.to_lowercase();
            let name_glob = pattern.get(prefix.len() + 1..).unwrap_or("");
            let regex = if name_glob.contains('[') {
                Some(
                    regex::Regex::new(&fnmatch_regex(name_glob))
                        .map_err(|e| Flow::Unsupported(e.to_string()))?,
                )
            } else {
                None
            };
            let found: Vec<Rc<str>> = if pattern.starts_with(&format!("{}:", prefix.to_lowercase()))
            {
                iam::action_names(prefix)
                    .iter()
                    .filter(|(_, lower)| match &regex {
                        Some(re) => re.is_match(lower),
                        None => glob(name_glob, lower),
                    })
                    .map(|(name, _)| Rc::from(format!("{prefix}:{name}").as_str()))
                    .collect()
            } else {
                Vec::new()
            };
            if found.is_empty() {
                vec![action.clone()]
            } else {
                found
            }
        };
        let expanded = Rc::new(expanded);
        EXPANDED.with(|m| m.borrow_mut().insert(action, expanded.clone()));
        Ok(expanded.iter().map(|a| Py::Str(a.clone())).collect())
    }
}

/// Wildcard actions and what they expand to.
pub(super) type Expansions = HashMap<Rc<str>, Rc<Vec<Rc<str>>>>;

/// `fnmatchcase` for a pattern of `*` and `?` (and literal characters).
/// `?` matches one character, as in Python, not one byte.
pub(super) fn glob(p: &str, s: &str) -> bool {
    if p.is_ascii() && s.is_ascii() {
        glob_units(p.as_bytes(), s.as_bytes(), b'*', b'?')
    } else {
        let (p, s): (Vec<char>, Vec<char>) = (p.chars().collect(), s.chars().collect());
        glob_units(&p, &s, '*', '?')
    }
}

pub(super) fn glob_units<T: Copy + PartialEq>(p: &[T], s: &[T], star_unit: T, any: T) -> bool {
    let (mut pi, mut si) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == any || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == star_unit {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == star_unit {
        pi += 1;
    }
    pi == p.len()
}

/// A stable sort by a fallible comparison (a bottom-up merge sort): the
/// first comparison that fails fails the sort, as a Python `TypeError`
/// does, and no comparison runs after it. `slice::sort_by` cannot be
/// used: a comparator that goes inconsistent after an error is no longer
/// a total order, which it may panic on.
pub(super) fn sort_fallible<T>(
    items: Vec<T>,
    mut cmp: impl FnMut(&T, &T) -> R<std::cmp::Ordering>,
) -> R<Vec<T>> {
    let n = items.len();
    let mut order: Vec<usize> = (0..n).collect();
    let mut scratch = order.clone();
    let mut width = 1;
    while width < n {
        let mut start = 0;
        while start < n {
            let mid = (start + width).min(n);
            let end = (start + 2 * width).min(n);
            let (mut l, mut r, mut k) = (start, mid, start);
            while l < mid && r < end {
                // Equal elements keep their order: take the right one only
                // when it is strictly less.
                if cmp(&items[order[r]], &items[order[l]])? == std::cmp::Ordering::Less {
                    scratch[k] = order[r];
                    r += 1;
                } else {
                    scratch[k] = order[l];
                    l += 1;
                }
                k += 1;
            }
            scratch[k..k + (mid - l)].copy_from_slice(&order[l..mid]);
            k += mid - l;
            scratch[k..k + (end - r)].copy_from_slice(&order[r..end]);
            start = end;
        }
        std::mem::swap(&mut order, &mut scratch);
        width *= 2;
    }
    let mut slots: Vec<Option<T>> = items.into_iter().map(Some).collect();
    Ok(order
        .into_iter()
        .map(|i| slots[i].take().expect("each index placed once"))
        .collect())
}

/// An element of bundled data: a container stays a view, a scalar is read.
pub(super) fn data_child(j: &'static Json) -> Py {
    match j {
        Json::Object(_) | Json::Array(_) => Py::Data(j),
        other => json_to_py(other),
    }
}
