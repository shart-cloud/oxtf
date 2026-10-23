use super::*;

impl<'p> Interp<'p> {
    #[expect(clippy::too_many_lines)]
    pub(super) fn method(
        &mut self,
        recv: Py,
        name: &str,
        args: Vec<Py>,
        kwargs: Vec<(String, Py)>,
    ) -> R<Py> {
        if let Py::Data(Json::Object(m)) = &recv {
            match name {
                "get" => {
                    let found = match args.first().map(|k| self.concrete(k)).transpose()? {
                        Some(Py::Str(k)) => m.get(&*k).map(data_child),
                        Some(_) => None,
                        None => return exc("TypeError"),
                    };
                    return Ok(found.unwrap_or_else(|| {
                        Self::arg(&args, &kwargs, 1, "default").unwrap_or(Py::None)
                    }));
                }
                "keys" => return Ok(Py::list(m.keys().map(|k| Py::str(k)).collect())),
                "values" => return Ok(Py::list(m.values().map(data_child).collect())),
                "items" => {
                    return Ok(Py::list(
                        m.iter()
                            .map(|(k, v)| Py::tuple(vec![Py::str(k), data_child(v)]))
                            .collect(),
                    ));
                }
                _ => {}
            }
        }
        let recv = self.concrete(&recv)?;
        if matches!(recv, Py::Instance(_)) {
            return self.call_method(recv, name, args, kwargs);
        }
        // A compiled pattern's methods are the `re` functions of it.
        if let Py::Pattern(p) = &recv
            && matches!(
                name,
                "match" | "search" | "fullmatch" | "findall" | "sub" | "split"
            )
        {
            let mut all = vec![Py::Pattern(p.clone())];
            all.extend(args);
            return self.builtin(&format!("re.{name}"), all, kwargs);
        }
        let a0 = args.first().cloned();
        Ok(match (&recv, name) {
            (Py::Dict(d), "get") => {
                let key = a0.ok_or_else(type_error)?;
                let found = self.dict_get(&d.borrow(), &key)?;
                self.note(d, &self.concrete(&key)?, found.is_some());
                match found {
                    Some(v) => v,
                    None => Self::arg(&args, &kwargs, 1, "default").unwrap_or(Py::None),
                }
            }
            (Py::Dict(d), "keys") => {
                let keys = Py::list(d.borrow().iter().map(|(k, _)| k.clone()).collect());
                let addr = Rc::as_ptr(d) as *const () as usize;
                if let (Some(path), Py::List(l)) = (self.paths.get(&addr), &keys) {
                    self.key_lists.borrow_mut().insert(
                        Rc::as_ptr(l) as *const () as usize,
                        (l.clone(), path.clone()),
                    );
                }
                keys
            }
            (Py::Dict(d), "values") => {
                Py::list(d.borrow().iter().map(|(_, v)| v.clone()).collect())
            }
            (Py::Dict(d), "items") => Py::list(
                d.borrow()
                    .iter()
                    .map(|(k, v)| Py::tuple(vec![k.clone(), v.clone()]))
                    .collect(),
            ),
            (Py::Dict(d), "copy") => Py::Dict(Rc::new(RefCell::new(d.borrow().clone()))),
            (Py::Dict(d), "pop") => {
                let key = self.concrete(&a0.ok_or_else(type_error)?)?;
                let pos = {
                    let items = d.borrow();
                    let mut found = None;
                    for (i, (k, _)) in items.iter().enumerate() {
                        if self.eq(k, &key)? {
                            found = Some(i);
                            break;
                        }
                    }
                    found
                };
                match pos {
                    Some(i) => d.borrow_mut().remove(i).1,
                    None => match args.get(1) {
                        Some(default) => default.clone(),
                        None => return exc("KeyError"),
                    },
                }
            }
            (Py::Dict(d), "update") => {
                let other = match a0.map(|o| self.concrete(&o)).transpose()? {
                    Some(Py::Dict(o)) => o.borrow().clone(),
                    None => Vec::new(),
                    _ => return unsupported("dict.update from pairs"),
                };
                let mut items = d.borrow().clone();
                for (k, v) in other
                    .into_iter()
                    .chain(kwargs.into_iter().map(|(k, v)| (Py::str(&k), v)))
                {
                    self.dict_insert(&mut items, k, v)?;
                }
                *d.borrow_mut() = items;
                Py::None
            }
            (Py::Dict(d), "setdefault") => {
                let key = a0.ok_or_else(type_error)?;
                let found = self.dict_get(&d.borrow(), &key)?;
                match found {
                    Some(v) => v,
                    None => {
                        let v = args.get(1).cloned().unwrap_or(Py::None);
                        // Insert on a copy: comparing keys must not hold
                        // the dict mutably.
                        let mut items = d.borrow().clone();
                        self.dict_insert(&mut items, key, v.clone())?;
                        *d.borrow_mut() = items;
                        v
                    }
                }
            }
            (Py::List(l), "append") => {
                l.borrow_mut().push(a0.ok_or_else(type_error)?);
                Py::None
            }
            (Py::List(l), "extend") => {
                let items = self.iterate(&a0.ok_or_else(type_error)?)?;
                l.borrow_mut().extend(items);
                Py::None
            }
            (Py::List(l), "insert") => {
                let len = l.borrow().len() as i64;
                let i = match self.concrete(&a0.ok_or_else(type_error)?)? {
                    Py::Int(i) => i,
                    _ => return exc("TypeError"),
                };
                let i = if i < 0 { (i + len).max(0) } else { i.min(len) };
                l.borrow_mut()
                    .insert(i as usize, args.get(1).cloned().ok_or_else(type_error)?);
                Py::None
            }
            (Py::List(_) | Py::Tuple(_), "index" | "count") => {
                let items = match &recv {
                    Py::List(l) => l.borrow().clone(),
                    Py::Tuple(t) => t.to_vec(),
                    _ => unreachable!("list or tuple"),
                };
                let needle = a0.ok_or_else(type_error)?;
                let mut hits = Vec::new();
                for (i, item) in items.iter().enumerate() {
                    if self.eq(item, &needle)? {
                        hits.push(i);
                        if name == "index" {
                            break;
                        }
                    }
                }
                if name == "count" {
                    Py::Int(hits.len() as i64)
                } else {
                    match hits.first() {
                        Some(&i) => Py::Int(i as i64),
                        None => return exc("ValueError"),
                    }
                }
            }
            (Py::List(l), "pop") => {
                let len = l.borrow().len();
                if len == 0 {
                    return exc("IndexError");
                }
                let i = match a0 {
                    Some(i) => self.index_of(&i, len)?,
                    None => len - 1,
                };
                l.borrow_mut().remove(i)
            }
            (Py::List(l), "remove") => {
                let needle = a0.ok_or_else(type_error)?;
                let items = l.borrow().clone();
                let mut pos = None;
                for (i, item) in items.iter().enumerate() {
                    if self.eq(item, &needle)? {
                        pos = Some(i);
                        break;
                    }
                }
                match pos {
                    Some(i) => {
                        l.borrow_mut().remove(i);
                        Py::None
                    }
                    None => return exc("ValueError"),
                }
            }
            (Py::List(l), "copy") => Py::list(l.borrow().clone()),
            (Py::List(l), "sort") => {
                let key = kwargs
                    .iter()
                    .find(|(k, _)| k == "key")
                    .map(|(_, v)| v.clone());
                let reverse = match kwargs.iter().find(|(k, _)| k == "reverse") {
                    Some((_, v)) => self.truthy(v)?,
                    None => false,
                };
                let items = l.borrow().clone();
                let mut keyed = Vec::new();
                for item in items {
                    let k = match &key {
                        Some(f) if !matches!(f, Py::None) => {
                            self.call_value(f, vec![item.clone()])?
                        }
                        _ => item.clone(),
                    };
                    keyed.push((k, item));
                }
                // A stable sort; the first comparison that fails (a
                // TypeError across types, an abstract value) fails the
                // call, as in Python. (`slice::sort_by` may panic on a
                // comparator that stops being a total order mid-sort.)
                let sorted = sort_fallible(keyed, |(a, _), (b, _)| {
                    let o = self.order(a, b)?;
                    Ok(if reverse { o.reverse() } else { o })
                })?;
                *l.borrow_mut() = sorted.into_iter().map(|(_, v)| v).collect();
                Py::None
            }
            (Py::Set(s), "add") => {
                let v = a0.ok_or_else(type_error)?;
                let items = s.borrow().clone();
                if !self.contains_seq(&items, &v)? {
                    s.borrow_mut().push(v);
                }
                Py::None
            }
            (Py::Set(s), "update") => {
                let mut items = s.borrow().clone();
                let mut members = Members::of(&items);
                for arg in &args {
                    for v in self.iterate(arg)? {
                        if !self.member(&members, &items, &v)? {
                            members.insert(&v);
                            items.push(v);
                        }
                    }
                }
                *s.borrow_mut() = items;
                Py::None
            }
            (Py::Set(s), "discard" | "remove") => {
                let v = a0.ok_or_else(type_error)?;
                let items = s.borrow().clone();
                let mut pos = None;
                for (i, item) in items.iter().enumerate() {
                    if self.eq(item, &v)? {
                        pos = Some(i);
                        break;
                    }
                }
                match pos {
                    Some(i) => {
                        s.borrow_mut().remove(i);
                    }
                    None if name == "remove" => return exc("KeyError"),
                    None => {}
                }
                Py::None
            }
            (Py::Set(s), "issubset" | "issuperset" | "intersection" | "difference" | "union") => {
                let other = self.iterate(&a0.ok_or_else(type_error)?)?;
                let mine = s.borrow().clone();
                match name {
                    "issubset" => Py::Bool(self.all_in(&mine, &other)?),
                    "issuperset" => Py::Bool(self.all_in(&other, &mine)?),
                    "union" => {
                        let mut all = mine;
                        all.extend(other);
                        Py::Set(Rc::new(RefCell::new(self.dedup(all)?)))
                    }
                    _ => {
                        let mut out = Vec::new();
                        let members = Members::of(&other);
                        for x in mine {
                            let inside = self.member(&members, &other, &x)?;
                            if inside == (name == "intersection") {
                                out.push(x);
                            }
                        }
                        Py::Set(Rc::new(RefCell::new(out)))
                    }
                }
            }
            (Py::Str(s), _) => self.str_method(s, name, &args, &kwargs)?,
            (Py::Match(groups), "group") => {
                let i = match a0.map(|a| self.concrete(&a)).transpose()? {
                    None => 0,
                    Some(Py::Int(i)) => i,
                    _ => return unsupported("named groups"),
                };
                let i = usize::try_from(i).map_err(|_| Flow::Exc(Rc::from("IndexError")))?;
                match groups.get(i) {
                    Some(g) => g.as_deref().map_or(Py::None, Py::str),
                    None => return exc("IndexError"),
                }
            }
            (Py::Match(groups), "groups") => Py::tuple(
                groups[1..]
                    .iter()
                    .map(|g| g.as_deref().map_or(Py::None, Py::str))
                    .collect(),
            ),
            (Py::None | Py::Bool(_) | Py::Int(_) | Py::Float(_), _) => {
                return exc("AttributeError");
            }
            (other, m) => {
                return if matches!(other, Py::List(_) | Py::Dict(_) | Py::Tuple(_) | Py::Set(_)) {
                    // A method these types do not have is AttributeError in
                    // Python; one they have but we do not model is outside the
                    // subset.
                    if known_method(other.type_name(), m) {
                        unsupported(format!("{}.{m}", other.type_name()))
                    } else {
                        exc("AttributeError")
                    }
                } else {
                    unsupported(format!("{}.{m}", other.type_name()))
                };
            }
        })
    }

    #[expect(clippy::too_many_lines)]
    pub(super) fn str_method(
        &mut self,
        s: &Rc<str>,
        name: &str,
        args: &[Py],
        kwargs: &[(String, Py)],
    ) -> R<Py> {
        if !kwargs.is_empty() && !matches!(name, "split" | "rsplit") {
            return unsupported(format!("str.{name} with keywords"));
        }
        let str_arg = |this: &Self, i: usize| -> R<Option<Rc<str>>> {
            match args.get(i).map(|a| this.concrete(a)).transpose()? {
                None | Some(Py::None) => Ok(None),
                Some(Py::Str(x)) => Ok(Some(x)),
                _ => exc("TypeError"),
            }
        };
        Ok(match name {
            "lower" => Py::str(&s.to_lowercase()),
            "upper" => Py::str(&s.to_uppercase()),
            "casefold" => Py::str(&s.to_lowercase()),
            "title" => Py::str(&title(s)),
            "strip" | "lstrip" | "rstrip" => {
                let chars = str_arg(self, 0)?;
                let pred = |c: char| match &chars {
                    Some(set) => set.contains(c),
                    None => c.is_whitespace(),
                };
                Py::str(match name {
                    "strip" => s.trim_matches(pred),
                    "lstrip" => s.trim_start_matches(pred),
                    _ => s.trim_end_matches(pred),
                })
            }
            "startswith" | "endswith" => {
                let prefixes: Vec<Rc<str>> =
                    match args.first().map(|a| self.concrete(a)).transpose()? {
                        Some(Py::Str(p)) => vec![p],
                        Some(Py::Tuple(ps)) => ps
                            .iter()
                            .map(|p| match self.concrete(p)? {
                                Py::Str(p) => Ok(p),
                                _ => exc("TypeError"),
                            })
                            .collect::<R<_>>()?,
                        _ => return exc("TypeError"),
                    };
                if args.len() > 1 {
                    return unsupported("startswith/endswith with bounds");
                }
                Py::Bool(prefixes.iter().any(|p| {
                    if name == "startswith" {
                        s.starts_with(&**p)
                    } else {
                        s.ends_with(&**p)
                    }
                }))
            }
            "split" | "rsplit" => {
                let sep = match Self::arg(args, kwargs, 0, "sep") {
                    None | Some(Py::None) => None,
                    Some(v) => match self.concrete(&v)? {
                        Py::Str(x) if x.is_empty() => return exc("ValueError"),
                        Py::Str(x) => Some(x),
                        _ => return exc("TypeError"),
                    },
                };
                let max = match Self::arg(args, kwargs, 1, "maxsplit") {
                    None => -1,
                    Some(v) => match self.concrete(&v)? {
                        Py::Int(i) => i,
                        _ => return exc("TypeError"),
                    },
                };
                Py::list(
                    split(s, sep.as_deref(), max, name == "rsplit")
                        .into_iter()
                        .map(|x| Py::str(&x))
                        .collect(),
                )
            }
            "replace" => {
                let (Some(old), Some(new)) = (str_arg(self, 0)?, str_arg(self, 1)?) else {
                    return exc("TypeError");
                };
                if args.len() > 2 {
                    return unsupported("str.replace with count");
                }
                Py::str(&s.replace(&*old, &new))
            }
            "join" => {
                let items = self.iterate(args.first().ok_or_else(type_error)?)?;
                let mut parts = Vec::new();
                for item in items {
                    match self.concrete(&item)? {
                        Py::Str(x) => parts.push(x.to_string()),
                        _ => return exc("TypeError"),
                    }
                }
                Py::str(&parts.join(s))
            }
            "find" | "rfind" | "index" | "count" => {
                let Some(sub) = str_arg(self, 0)? else {
                    return exc("TypeError");
                };
                if args.len() > 1 {
                    return unsupported("str search with bounds");
                }
                let chars = |byte: usize| s[..byte].chars().count() as i64;
                match name {
                    "count" => Py::Int(if sub.is_empty() {
                        s.chars().count() as i64 + 1
                    } else {
                        s.matches(&*sub).count() as i64
                    }),
                    "rfind" => Py::Int(s.rfind(&*sub).map_or(-1, chars)),
                    _ => match s.find(&*sub) {
                        Some(b) => Py::Int(chars(b)),
                        None if name == "index" => return exc("ValueError"),
                        None => Py::Int(-1),
                    },
                }
            }
            "isdigit" | "isnumeric" | "isdecimal" => Py::Bool(
                !s.is_empty()
                    && s.chars().all(|c| {
                        if name == "isnumeric" {
                            c.is_numeric()
                        } else {
                            c.is_ascii_digit() || c.is_numeric() && c.is_ascii_digit()
                        }
                    }),
            ),
            "isalpha" => Py::Bool(!s.is_empty() && s.chars().all(char::is_alphabetic)),
            "isalnum" => Py::Bool(!s.is_empty() && s.chars().all(char::is_alphanumeric)),
            "islower" => {
                Py::Bool(s.chars().any(char::is_lowercase) && !s.chars().any(char::is_uppercase))
            }
            "isupper" => {
                Py::Bool(s.chars().any(char::is_uppercase) && !s.chars().any(char::is_lowercase))
            }
            "removeprefix" | "removesuffix" => {
                let Some(fix) = str_arg(self, 0)? else {
                    return exc("TypeError");
                };
                Py::str(if name == "removeprefix" {
                    s.strip_prefix(&*fix).unwrap_or(s)
                } else {
                    s.strip_suffix(&*fix).unwrap_or(s)
                })
            }
            "partition" => {
                let Some(sep) = str_arg(self, 0)? else {
                    return exc("TypeError");
                };
                match s.split_once(&*sep) {
                    Some((a, b)) => Py::tuple(vec![Py::str(a), Py::str(&sep), Py::str(b)]),
                    None => Py::tuple(vec![Py::str(s), Py::str(""), Py::str("")]),
                }
            }
            "zfill" => {
                let width = match args.first().map(|a| self.concrete(a)).transpose()? {
                    Some(Py::Int(w)) => w.max(0) as usize,
                    _ => return exc("TypeError"),
                };
                let n = s.chars().count();
                if n >= width {
                    Py::Str(s.clone())
                } else {
                    let (sign, rest) = match s.chars().next() {
                        Some(c @ ('+' | '-')) => (c.to_string(), &s[1..]),
                        _ => (String::new(), &s[..]),
                    };
                    Py::str(&format!("{sign}{}{rest}", "0".repeat(width - n)))
                }
            }
            "splitlines" => Py::list(s.lines().map(Py::str).collect()),
            "encode" | "decode" | "format" => return unsupported(format!("str.{name}")),
            _ => return exc("AttributeError"),
        })
    }

    /// Python's `str()`.
    pub(super) fn to_str(&self, v: &Py) -> R<String> {
        Ok(match v {
            Py::Str(s) => s.to_string(),
            other => self.repr(other)?,
        })
    }

    pub(super) fn repr(&self, v: &Py) -> R<String> {
        Ok(match self.concrete(v)? {
            Py::None => "None".into(),
            Py::Bool(b) => if b { "True" } else { "False" }.into(),
            Py::Int(i) => i.to_string(),
            Py::Float(f) => py::float_repr(f),
            Py::Str(s) => py::repr(&Json::String(s.to_string()))
                .ok_or_else(|| Flow::Unsupported("repr".into()))?,
            Py::List(l) => format!("[{}]", self.reprs(&l.borrow().clone())?),
            Py::Tuple(t) if t.len() == 1 => format!("({},)", self.repr(&t[0])?),
            Py::Tuple(t) => format!("({})", self.reprs(&t)?),
            Py::Dict(d) => {
                let items = d.borrow().clone();
                let parts: Vec<String> = items
                    .iter()
                    .map(|(k, v)| Ok(format!("{}: {}", self.repr(k)?, self.repr(v)?)))
                    .collect::<R<_>>()?;
                format!("{{{}}}", parts.join(", "))
            }
            Py::Result(r) => format!("CheckResult.{r}"),
            Py::Exception(name) => name.to_string(),
            other => return unsupported(format!("str of {}", other.type_name())),
        })
    }

    pub(super) fn reprs(&self, items: &[Py]) -> R<String> {
        Ok(items
            .iter()
            .map(|x| self.repr(x))
            .collect::<R<Vec<_>>>()?
            .join(", "))
    }

    /// Python's `int(x)`; `None` where it raises ValueError.
    pub(super) fn to_int(&self, v: &Py) -> R<Option<i64>> {
        Ok(match v {
            Py::Int(i) => Some(*i),
            Py::Bool(b) => Some(*b as i64),
            Py::Float(f) if f.is_finite() => Some(f.trunc() as i64),
            Py::Float(_) => return exc("OverflowError"),
            Py::Str(s) => py::int_str(s).and_then(|i| i64::try_from(i).ok()),
            _ => return exc("TypeError"),
        })
    }

    pub(super) fn to_float(&self, v: &Py) -> R<Option<f64>> {
        Ok(match v {
            Py::Int(i) => Some(*i as f64),
            Py::Bool(b) => Some(*b as i64 as f64),
            Py::Float(f) => Some(*f),
            Py::Str(s) => parse_float(s),
            _ => return exc("TypeError"),
        })
    }
}

pub(super) fn known_method(ty: &str, m: &str) -> bool {
    let methods: &[&str] = match ty {
        "list" => &[
            "append", "clear", "copy", "count", "extend", "index", "insert", "pop", "remove",
            "reverse", "sort",
        ],
        "dict" => &[
            "clear",
            "copy",
            "fromkeys",
            "get",
            "items",
            "keys",
            "pop",
            "popitem",
            "setdefault",
            "update",
            "values",
        ],
        "tuple" => &["count", "index"],
        "set" => &[
            "add",
            "clear",
            "copy",
            "difference",
            "discard",
            "intersection",
            "isdisjoint",
            "issubset",
            "issuperset",
            "pop",
            "remove",
            "symmetric_difference",
            "union",
            "update",
        ],
        _ => &[],
    };
    methods.contains(&m)
}

pub(super) fn type_error() -> Flow {
    Flow::Exc(Rc::from("TypeError"))
}

pub(super) fn overflow() -> Flow {
    Flow::Unsupported("integer overflow".into())
}

pub(super) fn number(v: &Py) -> Option<f64> {
    match v {
        Py::Bool(b) => Some(*b as i64 as f64),
        Py::Int(i) => Some(*i as f64),
        Py::Float(f) => Some(*f),
        _ => None,
    }
}

pub(super) fn range_items(a: i64, b: i64, s: i64) -> Vec<i64> {
    let mut out = Vec::new();
    let mut i = a;
    while (s > 0 && i < b) || (s < 0 && i > b) {
        out.push(i);
        if out.len() > 1_000_000 {
            break;
        }
        i += s;
    }
    out
}

pub(super) fn range_len(a: i64, b: i64, s: i64) -> usize {
    if s > 0 && b > a {
        ((b - a + s - 1) / s) as usize
    } else if s < 0 && a > b {
        ((a - b - s - 1) / -s) as usize
    } else {
        0
    }
}

pub(super) fn target_names(t: &Target, out: &mut Vec<String>) {
    match t {
        Target::Name { id } => out.push(id.clone()),
        Target::Tuple { elts } => elts.iter().for_each(|e| target_names(e, out)),
        _ => {}
    }
}

pub(super) fn title(s: &str) -> String {
    let mut out = String::new();
    let mut prev_cased = false;
    for c in s.chars() {
        if c.is_alphabetic() {
            if prev_cased {
                out.extend(c.to_lowercase());
            } else {
                out.extend(c.to_uppercase());
            }
            prev_cased = true;
        } else {
            out.push(c);
            prev_cased = false;
        }
    }
    out
}

/// Python's `str.split` / `rsplit`.
pub(super) fn split(s: &str, sep: Option<&str>, max: i64, from_right: bool) -> Vec<String> {
    let max = if max < 0 { usize::MAX } else { max as usize };
    match sep {
        Some(sep) => {
            let parts: Vec<&str> = if from_right {
                let mut v: Vec<&str> = s.rsplitn(max.saturating_add(1), sep).collect();
                v.reverse();
                v
            } else {
                s.splitn(max.saturating_add(1), sep).collect()
            };
            parts.into_iter().map(str::to_string).collect()
        }
        None => {
            // Runs of whitespace; leading and trailing whitespace ignored.
            let words: Vec<&str> = s.split_whitespace().collect();
            if words.len() <= max.saturating_add(1) || max == usize::MAX {
                return words.into_iter().map(str::to_string).collect();
            }
            if from_right {
                let keep = &words[words.len() - max..];
                let head_end = {
                    // The remainder keeps its inner whitespace.
                    let mut idx = s.trim_end().len();
                    for w in keep.iter().rev() {
                        idx = s[..idx].rfind(w).unwrap_or(0);
                        idx = s[..idx].trim_end().len();
                    }
                    idx
                };
                let mut out = vec![s[..head_end].trim_start().to_string()];
                out.extend(keep.iter().map(|w| w.to_string()));
                out
            } else {
                let mut out: Vec<String> = Vec::new();
                let mut rest = s.trim_start();
                for _ in 0..max {
                    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
                    out.push(rest[..end].to_string());
                    rest = rest[end..].trim_start();
                }
                out.push(rest.to_string());
                out
            }
        }
    }
}

pub(super) fn parse_float(s: &str) -> Option<f64> {
    let t = s.trim().replace('_', "");
    match t.to_ascii_lowercase().trim_start_matches(['+', '-']) {
        "inf" | "infinity" => Some(if t.starts_with('-') {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        }),
        "nan" => Some(f64::NAN),
        _ => {
            let ok = !t.is_empty() && t.chars().all(|c| c.is_ascii_digit() || "+-.eE".contains(c));
            if ok { t.parse().ok() } else { None }
        }
    }
}

/// `fnmatch.translate` for the subset the checks use: `*`, `?`, `[...]`.
pub(super) fn fnmatch_regex(p: &str) -> String {
    let mut out = String::from("(?s)\\A");
    let chars: Vec<char> = p.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            '[' => match chars[i + 1..].iter().position(|&c| c == ']') {
                Some(end) if end > 0 => {
                    let inner: String = chars[i + 1..i + 1 + end].iter().collect();
                    let inner = inner
                        .strip_prefix('!')
                        .map_or(inner.clone(), |r| format!("^{r}"));
                    out.push('[');
                    out.push_str(&inner.replace('\\', "\\\\"));
                    out.push(']');
                    i += end + 1;
                }
                _ => out.push_str("\\["),
            },
            c => out.push_str(&regex::escape(c.encode_utf8(&mut [0; 4]))),
        }
        i += 1;
    }
    out.push_str("\\z");
    out
}

/// Whether `p` is a pattern this interpreter can run: one `pyre`
/// translates, or a [`Bounded`] one.
pub(super) fn check_pattern(p: &str) -> Result<(), String> {
    match Bounded::parse(p) {
        Some(b) => b.map(|_| ()).map_err(|f| match f {
            Flow::Unsupported(why) => why,
            _ => "pattern".into(),
        }),
        None => pyre::translate(p).map(|_| ()),
    }
}
