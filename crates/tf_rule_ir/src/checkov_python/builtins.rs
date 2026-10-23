use super::*;

impl<'p> Interp<'p> {
    #[expect(clippy::too_many_lines)]
    pub(super) fn builtin(
        &mut self,
        name: &str,
        args: Vec<Py>,
        kwargs: Vec<(String, Py)>,
    ) -> R<Py> {
        let a0 = args.first().cloned();
        Ok(match name {
            "len" => {
                let v = a0.ok_or_else(type_error)?;
                if let Py::Data(j) = &v {
                    return Ok(Py::Int(match j {
                        Json::Object(m) => m.len(),
                        Json::Array(a) => a.len(),
                        _ => return exc("TypeError"),
                    } as i64));
                }
                let v = self.concrete(&v)?;
                Py::Int(match v {
                    Py::Str(s) => s.chars().count(),
                    Py::List(l) | Py::Set(l) => l.borrow().len(),
                    Py::Tuple(t) => t.len(),
                    Py::Dict(d) => d.borrow().len(),
                    Py::Range(a, b, s) => range_len(a, b, s),
                    _ => return exc("TypeError"),
                } as i64)
            }
            "isinstance" => {
                // Bundled data keeps its type without being copied.
                let v = match a0.ok_or_else(type_error)? {
                    data @ Py::Data(_) => data,
                    other => self.concrete(&other)?,
                };
                let types = match args.get(1).map(|t| self.concrete(t)).transpose()? {
                    Some(Py::Type(t)) => vec![t],
                    Some(Py::Tuple(ts)) => ts
                        .iter()
                        .map(|t| match self.concrete(t)? {
                            Py::Type(t) => Ok(t),
                            _ => exc("TypeError"),
                        })
                        .collect::<R<_>>()?,
                    _ => return exc("TypeError"),
                };
                let actual = match &v {
                    Py::Instance(i) => format!("class:{}", i.class),
                    other => other.type_name().to_string(),
                };
                let actual = actual.as_str();
                Py::Bool(
                    types
                        .iter()
                        .any(|t| **t == *actual || (&**t == "int" && actual == "bool")),
                )
            }
            "any" | "all" => {
                let want = name == "any";
                let items = self.iterate(&a0.ok_or_else(type_error)?)?;
                let mut hit = false;
                for item in &items {
                    if self.truthy(item)? == want {
                        hit = true;
                        break;
                    }
                }
                Py::Bool(if want { hit } else { !hit })
            }
            "enumerate" => {
                let start = match Self::arg(&args, &kwargs, 1, "start") {
                    Some(v) => match self.concrete(&v)? {
                        Py::Int(i) => i,
                        _ => return exc("TypeError"),
                    },
                    None => 0,
                };
                let items = self.iterate(&a0.ok_or_else(type_error)?)?;
                Py::list(
                    items
                        .into_iter()
                        .enumerate()
                        .map(|(i, v)| Py::tuple(vec![Py::Int(start + i as i64), v]))
                        .collect(),
                )
            }
            "range" => {
                let ints: Vec<i64> = args
                    .iter()
                    .map(|a| match self.concrete(a)? {
                        Py::Int(i) => Ok(i),
                        Py::Bool(b) => Ok(b as i64),
                        _ => exc("TypeError"),
                    })
                    .collect::<R<_>>()?;
                match ints[..] {
                    [b] => Py::Range(0, b, 1),
                    [a, b] => Py::Range(a, b, 1),
                    [_, _, 0] => return exc("ValueError"),
                    [a, b, s] => Py::Range(a, b, s),
                    _ => return exc("TypeError"),
                }
            }
            "sorted" => {
                let items = self.iterate(&a0.ok_or_else(type_error)?)?;
                let out = Py::list(items);
                self.method(out.clone(), "sort", Vec::new(), kwargs)?;
                out
            }
            "reversed" => {
                let mut items = self.iterate(&a0.ok_or_else(type_error)?)?;
                items.reverse();
                Py::list(items)
            }
            "min" | "max" => {
                let items = if args.len() == 1 {
                    self.iterate(&args[0])?
                } else {
                    args.clone()
                };
                let key = kwargs
                    .iter()
                    .find(|(k, _)| k == "key")
                    .map(|(_, v)| v.clone());
                let mut best: Option<(Py, Py)> = None;
                for item in items {
                    let k = match &key {
                        Some(f) => self.call_value(f, vec![item.clone()])?,
                        None => item.clone(),
                    };
                    let better = match &best {
                        None => true,
                        Some((bk, _)) => {
                            let o = self.order(&k, bk)?;
                            if name == "min" { o.is_lt() } else { o.is_gt() }
                        }
                    };
                    if better {
                        best = Some((k, item));
                    }
                }
                match best {
                    Some((_, v)) => v,
                    None => match kwargs.iter().find(|(k, _)| k == "default") {
                        Some((_, d)) => d.clone(),
                        None => return exc("ValueError"),
                    },
                }
            }
            "sum" => {
                let mut total = Self::arg(&args, &kwargs, 1, "start").unwrap_or(Py::Int(0));
                for item in self.iterate(&a0.ok_or_else(type_error)?)? {
                    total = self.binop(BinOp::Add, &total, &item, false)?;
                }
                total
            }
            "zip" => {
                let lists: Vec<Vec<Py>> = args.iter().map(|a| self.iterate(a)).collect::<R<_>>()?;
                let n = lists.iter().map(Vec::len).min().unwrap_or(0);
                Py::list(
                    (0..n)
                        .map(|i| Py::tuple(lists.iter().map(|l| l[i].clone()).collect()))
                        .collect(),
                )
            }
            "list" | "tuple" | "set" => {
                let items = match a0 {
                    Some(v) => self.iterate(&v)?,
                    None => Vec::new(),
                };
                match name {
                    "list" => Py::list(items),
                    "tuple" => Py::tuple(items),
                    _ => Py::Set(Rc::new(RefCell::new(self.dedup(items)?))),
                }
            }
            "dict" => {
                let mut out = Vec::new();
                if let Some(v) = a0 {
                    match self.concrete(&v)? {
                        Py::Dict(d) => out = d.borrow().clone(),
                        other => {
                            for pair in self.iterate(&other)? {
                                let kv = self.iterate(&pair)?;
                                let [k, v] = &kv[..] else {
                                    return exc("ValueError");
                                };
                                self.dict_insert(&mut out, k.clone(), v.clone())?;
                            }
                        }
                    }
                }
                for (k, v) in kwargs {
                    self.dict_insert(&mut out, Py::str(&k), v)?;
                }
                Py::Dict(Rc::new(RefCell::new(out)))
            }
            "bool" => Py::Bool(match a0 {
                Some(v) => self.truthy(&v)?,
                None => false,
            }),
            "str" => match a0 {
                Some(v) => Py::str(&self.to_str(&self.concrete(&v)?)?),
                None => Py::str(""),
            },
            "int" => {
                let v = self.concrete(&a0.ok_or_else(type_error)?)?;
                match self.to_int(&v)? {
                    Some(i) => Py::Int(i),
                    None => return exc("ValueError"),
                }
            }
            "float" => {
                let v = self.concrete(&a0.ok_or_else(type_error)?)?;
                match self.to_float(&v)? {
                    Some(f) => Py::Float(f),
                    None => return exc("ValueError"),
                }
            }
            "abs" => match self.concrete(&a0.ok_or_else(type_error)?)? {
                Py::Int(i) => Py::Int(i.checked_abs().ok_or_else(overflow)?),
                Py::Bool(b) => Py::Int(b as i64),
                Py::Float(f) => Py::Float(f.abs()),
                _ => return exc("TypeError"),
            },
            "round" => match self.concrete(&a0.ok_or_else(type_error)?)? {
                Py::Int(i) if args.len() == 1 => Py::Int(i),
                Py::Float(f) if args.len() == 1 => {
                    // Banker's rounding, as Python's round().
                    let r = f.round();
                    let r = if (f - f.trunc()).abs() == 0.5 {
                        2.0 * (f / 2.0).round()
                    } else {
                        r
                    };
                    Py::Int(r as i64)
                }
                _ => return unsupported("round with ndigits"),
            },
            "force_list" => {
                let v = a0.ok_or_else(type_error)?;
                match self.concrete(&v)? {
                    Py::List(_) => v,
                    _ => Py::list(vec![v]),
                }
            }
            "force_int" => {
                let v = self.concrete(&a0.ok_or_else(type_error)?)?;
                match v {
                    Py::Int(_) | Py::Bool(_) => v,
                    other => match self.to_int(&other) {
                        Ok(Some(i)) => Py::Int(i),
                        Ok(None) | Err(Flow::Exc(_)) => Py::None,
                        Err(f) => return Err(f),
                    },
                }
            }
            "force_float" => {
                let v = self.concrete(&a0.ok_or_else(type_error)?)?;
                match v {
                    Py::Float(_) => v,
                    other => match self.to_float(&other) {
                        Ok(Some(f)) => Py::Float(f),
                        Ok(None) | Err(Flow::Exc(_)) => Py::None,
                        Err(f) => return Err(f),
                    },
                }
            }
            "re.compile" => match self.concrete(&a0.ok_or_else(type_error)?)? {
                Py::Str(p) | Py::Pattern(p) => {
                    if args.len() > 1 || !kwargs.is_empty() {
                        return unsupported("regex flags");
                    }
                    check_pattern(&p).map_err(Flow::Unsupported)?;
                    Py::Pattern(p)
                }
                _ => return exc("TypeError"),
            },
            "re.match" | "re.search" | "re.fullmatch" | "re.findall" | "re.sub" | "re.split" => {
                if !kwargs.is_empty() || (name != "re.sub" && args.len() > 2) || args.len() > 3 {
                    return unsupported("regex flags or count");
                }
                let pattern = match self.concrete(&a0.ok_or_else(type_error)?)? {
                    Py::Str(p) | Py::Pattern(p) => p,
                    _ => return exc("TypeError"),
                };
                let subject_at = if name == "re.sub" { 2 } else { 1 };
                let subject = match args.get(subject_at).map(|s| self.concrete(s)).transpose()? {
                    Some(Py::Str(s)) => s,
                    _ => return exc("TypeError"),
                };
                self.regex(name, &pattern, &subject, args.get(1))?
            }
            "fnmatch.fnmatch" | "fnmatch.fnmatchcase" => {
                let (Some(n), Some(p)) = (a0, args.get(1)) else {
                    return exc("TypeError");
                };
                match (self.concrete(&n)?, self.concrete(p)?) {
                    (Py::Str(n), Py::Str(p)) if !p.contains('[') => Py::Bool(glob(&p, &n)),
                    (Py::Str(n), Py::Str(p)) => {
                        thread_local! {
                            static COMPILED: RefCell<HashMap<Rc<str>, regex::Regex>> = RefCell::new(HashMap::default());
                        }
                        let re = match COMPILED.with(|m| m.borrow().get(&p).cloned()) {
                            Some(re) => re,
                            None => {
                                let re = regex::Regex::new(&fnmatch_regex(&p))
                                    .map_err(|e| Flow::Unsupported(e.to_string()))?;
                                COMPILED.with(|m| m.borrow_mut().insert(p.clone(), re.clone()));
                                re
                            }
                        };
                        Py::Bool(re.is_match(&n))
                    }
                    _ => return exc("TypeError"),
                }
            }
            // Checkov's `is_terraform_variable_dependent`: a string that still
            // reads as a reference. An unresolved reference is abstract here.
            "is_terraform_variable_dependent" => {
                match self.concrete(&a0.ok_or_else(type_error)?)? {
                    Py::Str(s) => {
                        const PREFIXES: &[&str] = &[
                            "var.",
                            "local.",
                            "module.",
                            "data.",
                            "aws_",
                            "azurerm_",
                            "azuread_",
                            "digitalocean_",
                            "google_",
                            "github_",
                            "kubernetes_",
                            "linode_",
                            "oci_",
                            "openstack_",
                            "yandex_",
                            "lookup(",
                            "list(",
                            "file(",
                        ];
                        Py::Bool(PREFIXES.iter().any(|p| s.starts_with(p)) || s.contains("${"))
                    }
                    _ => Py::Bool(false),
                }
            }
            "type" => Py::Type(Rc::from(
                self.concrete(&a0.ok_or_else(type_error)?)?.type_name(),
            )),
            "typing.cast" => args.get(1).cloned().ok_or_else(type_error)?,
            n if n.starts_with("iam.") => return self.iam_builtin(n, args, kwargs),
            "hasattr" => {
                let (Some(obj), Some(Py::Str(name))) =
                    (a0, args.get(1).map(|n| self.concrete(n)).transpose()?)
                else {
                    return exc("TypeError");
                };
                match self.get_attr(&obj, &name) {
                    Ok(_) => Py::Bool(true),
                    Err(Flow::Exc(e)) if &*e == "AttributeError" => Py::Bool(false),
                    Err(f) => return Err(f),
                }
            }
            "yaml.safe_load" => match self.concrete(&a0.ok_or_else(type_error)?)? {
                Py::Str(s) => match tf_yaml::pyyaml::load(&s) {
                    Ok(doc) => json_to_py(&doc.value),
                    Err(_) => return exc("YAMLError"),
                },
                _ => return exc("YAMLError"),
            },
            "itertools.chain" => {
                let mut out = Vec::new();
                for a in &args {
                    out.extend(self.iterate(a)?);
                }
                Py::list(out)
            }
            "dpath.search" | "dpath.get" => {
                let (Some(obj), Some(Py::Str(glob))) =
                    (a0, args.get(1).map(|n| self.concrete(n)).transpose()?)
                else {
                    return exc("TypeError");
                };
                let matches = self.dpath(&obj, &glob)?;
                if name == "dpath.search" {
                    // Only its truthiness is used: whether anything matched.
                    let found: Vec<(Py, Py)> =
                        matches.into_iter().map(|v| (Py::str(&glob), v)).collect();
                    Py::Dict(Rc::new(RefCell::new(found)))
                } else {
                    match matches.len() {
                        0 => return exc("KeyError"),
                        1 => matches.into_iter().next().expect("one match"),
                        _ => return exc("ValueError"),
                    }
                }
            }
            "ipaddress.ip_network" | "ipaddress.ip_address" => {
                let address = name == "ipaddress.ip_address";
                if !kwargs.is_empty() || args.len() > 1 {
                    return unsupported("ip_network with strict=");
                }
                let text = match self.concrete(&a0.ok_or_else(type_error)?)? {
                    Py::Str(s) => s,
                    _ => return unsupported("ip_network of a non-string"),
                };
                let Some(net) = py::network_str(&text) else {
                    return exc("ValueError");
                };
                if address && text.contains('/') {
                    return exc("ValueError");
                }
                // strict=True: a network whose address has host bits set is
                // a ValueError.
                if let Some((host, _)) = text.split_once('/') {
                    let first = |n: py::Network| match n {
                        py::Network::V4 { first, .. } => first as u128,
                        py::Network::V6 { first, .. } => first,
                    };
                    match py::network_str(host) {
                        Some(addr) if first(addr) == first(net) => {}
                        _ => return exc("ValueError"),
                    }
                }
                Py::Net(net, address)
            }
            "map" | "filter" => {
                let f = a0.ok_or_else(type_error)?;
                let items = self.iterate(args.get(1).ok_or_else(type_error)?)?;
                let mut out = Vec::new();
                for item in items {
                    if name == "map" {
                        out.push(self.call_value(&f, vec![item])?);
                    } else {
                        let keep = match &f {
                            Py::None => self.truthy(&item)?,
                            f => {
                                let v = self.call_value(f, vec![item.clone()])?;
                                self.truthy(&v)?
                            }
                        };
                        if keep {
                            out.push(item);
                        }
                    }
                }
                Py::list(out)
            }
            "json.loads" => {
                if !kwargs.is_empty() {
                    return unsupported("json.loads with keywords");
                }
                match self.concrete(&a0.ok_or_else(type_error)?)? {
                    Py::Str(s) => match serde_json::from_str::<Json>(&s) {
                        Ok(j) => json_to_py(&j),
                        Err(_) => return exc("JSONDecodeError"),
                    },
                    _ => return exc("TypeError"),
                }
            }
            "json.dumps" => {
                if !kwargs.is_empty() {
                    return unsupported("json.dumps with keywords");
                }
                let v = a0.ok_or_else(type_error)?;
                Py::str(&self.json_dumps(&v)?)
            }
            "value_check" => {
                let check = self
                    .program
                    .value_check
                    .as_ref()
                    .and_then(|m| m.get(&*self.resource.ty))
                    .ok_or_else(|| Flow::Unsupported("no value check for this type".into()))?;
                let v = check.evaluate(self.resource);
                *self.delegated.borrow_mut() = v.witness.clone();
                match v.truth {
                    Truth::True => Py::Result(Rc::from("FAILED")),
                    Truth::False => Py::Result(Rc::from("PASSED")),
                    t => match v.witness {
                        Some(w) => return Err(Flow::Abstract(Rc::new(w), t == Truth::Tainted)),
                        None => Py::Result(Rc::from("UNKNOWN")),
                    },
                }
            }
            other => return unsupported(format!("builtin {other}")),
        })
    }

    /// `dpath`'s glob over `obj`: `/`-separated segments, each matched with
    /// `fnmatch` against dict keys and list indices (so `[0]` matches index
    /// 0). `**` is not read.
    pub(super) fn dpath(&self, obj: &Py, glob: &str) -> R<Vec<Py>> {
        let segments: Vec<&str> = glob.split('/').filter(|s| !s.is_empty()).collect();
        if segments.contains(&"**") {
            return unsupported("dpath **");
        }
        let mut current = vec![obj.clone()];
        for seg in segments {
            let re = regex::Regex::new(&fnmatch_regex(seg))
                .map_err(|e| Flow::Unsupported(e.to_string()))?;
            let mut next = Vec::new();
            for v in current {
                match self.concrete(&v)? {
                    Py::Dict(d) => {
                        for (k, x) in d.borrow().iter() {
                            if let Py::Str(k) = k
                                && re.is_match(k)
                            {
                                next.push(x.clone());
                            }
                        }
                    }
                    Py::List(l) => {
                        for (i, x) in l.borrow().iter().enumerate() {
                            if re.is_match(&i.to_string()) {
                                next.push(x.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }
            current = next;
        }
        Ok(current)
    }

    /// `json.dumps` with its default separators and `ensure_ascii`.
    pub(super) fn json_dumps(&self, v: &Py) -> R<String> {
        Ok(match self.concrete(v)? {
            Py::None => "null".into(),
            Py::Bool(b) => if b { "true" } else { "false" }.into(),
            Py::Int(i) => i.to_string(),
            Py::Float(f) if f.is_finite() => py::float_repr(f),
            Py::Float(f) if f.is_nan() => "NaN".into(),
            Py::Float(f) => if f > 0.0 { "Infinity" } else { "-Infinity" }.into(),
            Py::Str(s) => {
                let mut out = String::from("\"");
                for c in s.chars() {
                    match c {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        '\x08' => out.push_str("\\b"),
                        '\x0c' => out.push_str("\\f"),
                        c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                            let mut buf = [0u16; 2];
                            for unit in c.encode_utf16(&mut buf) {
                                out.push_str(&format!("\\u{unit:04x}"));
                            }
                        }
                        c => out.push(c),
                    }
                }
                out.push('"');
                out
            }
            Py::List(l) => {
                let items = l.borrow().clone();
                format!(
                    "[{}]",
                    items
                        .iter()
                        .map(|x| self.json_dumps(x))
                        .collect::<R<Vec<_>>>()?
                        .join(", ")
                )
            }
            Py::Tuple(t) => format!(
                "[{}]",
                t.iter()
                    .map(|x| self.json_dumps(x))
                    .collect::<R<Vec<_>>>()?
                    .join(", ")
            ),
            Py::Dict(d) => {
                let items = d.borrow().clone();
                let mut parts = Vec::new();
                for (k, v) in &items {
                    let key = match self.concrete(k)? {
                        Py::Str(s) => self.json_dumps(&Py::Str(s))?,
                        Py::Int(i) => format!("\"{i}\""),
                        Py::Bool(b) => format!("\"{}\"", if b { "true" } else { "false" }),
                        Py::None => "\"null\"".into(),
                        _ => return exc("TypeError"),
                    };
                    parts.push(format!("{key}: {}", self.json_dumps(v)?));
                }
                format!("{{{}}}", parts.join(", "))
            }
            _ => return exc("TypeError"),
        })
    }

    pub(super) fn regex(
        &self,
        name: &str,
        pattern: &str,
        subject: &str,
        repl: Option<&Py>,
    ) -> R<Py> {
        let compile = |p: &str, mode| pyre::compile(p, mode).map_err(Flow::Unsupported);
        let groups = |c: regex::Captures| -> Py {
            Py::Match(Rc::new(
                c.iter().map(|g| g.map(|m| Rc::from(m.as_str()))).collect(),
            ))
        };
        if let Some(bounded) = Bounded::parse(pattern) {
            return match name {
                "re.match" | "re.search" => bounded?
                    .find(subject, name == "re.search")?
                    .map_or(Ok(Py::None), |g| Ok(Py::Match(Rc::new(g)))),
                _ => unsupported("lookaround outside re.match / re.search"),
            };
        }
        Ok(match name {
            "re.match" => compile(pattern, pyre::Mode::Match)?
                .captures(subject)
                .map_or(Py::None, groups),
            "re.search" => compile(pattern, pyre::Mode::Search)?
                .captures(subject)
                .map_or(Py::None, groups),
            "re.fullmatch" => compile(&format!("(?:{pattern})\\Z"), pyre::Mode::Match)?
                .captures(subject)
                .map_or(Py::None, groups),
            "re.findall" => {
                let re = compile(pattern, pyre::Mode::Search)?;
                let n = re.captures_len() - 1;
                Py::list(
                    re.captures_iter(subject)
                        .map(|c| match n {
                            0 => Py::str(c.get(0).map_or("", |m| m.as_str())),
                            1 => Py::str(c.get(1).map_or("", |m| m.as_str())),
                            _ => Py::tuple(
                                (1..=n)
                                    .map(|i| Py::str(c.get(i).map_or("", |m| m.as_str())))
                                    .collect(),
                            ),
                        })
                        .collect(),
                )
            }
            "re.sub" => {
                let repl = match repl.map(|r| self.concrete(r)).transpose()? {
                    Some(Py::Str(r)) if !r.contains('\\') => r,
                    _ => return unsupported("re.sub replacement"),
                };
                let re = compile(pattern, pyre::Mode::Search)?;
                Py::str(&re.replace_all(subject, regex::NoExpand(&repl)))
            }
            "re.split" => {
                let re = compile(pattern, pyre::Mode::Search)?;
                if re.captures_len() > 1 {
                    return unsupported("re.split with groups");
                }
                Py::list(re.split(subject).map(Py::str).collect())
            }
            _ => unreachable!("regex builtins"),
        })
    }
}

/// A pattern with a lookbehind `(?<![class])` at its start and/or a
/// lookahead `(?![class])` at its end (the `regex` crate has neither):
/// the core is matched anchored at each start, and the characters before
/// and after are tested against the classes. Exact when the core has one
/// match per start (a fixed-width core, as Checkov's AWS key pattern);
/// Python would also backtrack into a shorter core match.
pub(super) struct Bounded {
    pub(super) behind: Option<regex::Regex>,
    pub(super) core: regex::Regex,
    pub(super) ahead: Option<regex::Regex>,
}

impl Bounded {
    pub(super) fn parse(pattern: &str) -> Option<R<Bounded>> {
        // Global inline flags stay in front of every part.
        let (flags, rest) = match pattern.strip_prefix("(?") {
            Some(r)
                if r.find(')')
                    .is_some_and(|i| r[..i].chars().all(|c| c.is_ascii_alphabetic()) && i > 0) =>
            {
                let i = r.find(')').expect("checked");
                (&pattern[..i + 3], &r[i + 1..])
            }
            _ => ("", pattern),
        };
        let class = |s: &str| s.starts_with('[') && s.ends_with(']') && !s.contains(['(', ')']);
        let (behind, rest) = match rest
            .strip_prefix("(?<!")
            .and_then(|r| r.find("])").map(|i| (r, i)))
        {
            Some((r, i)) if class(&r[..i + 1]) => (Some(&r[..i + 1]), &r[i + 2..]),
            _ => (None, rest),
        };
        let (ahead, core) = match rest.rfind("(?!") {
            Some(i) if rest.ends_with("])") && class(&rest[i + 3..rest.len() - 1]) => {
                (Some(&rest[i + 3..rest.len() - 1]), &rest[..i])
            }
            _ => (None, rest),
        };
        if behind.is_none() && ahead.is_none() {
            return None;
        }
        let compile = |p: &str| {
            pyre::compile(&format!("{flags}{p}"), pyre::Mode::Match).map_err(Flow::Unsupported)
        };
        Some((|| {
            Ok(Bounded {
                behind: behind.map(compile).transpose()?,
                core: compile(&format!("(?:{core})"))?,
                ahead: ahead.map(compile).transpose()?,
            })
        })())
    }

    pub(super) fn find(&self, subject: &str, search: bool) -> R<Option<Vec<Option<Rc<str>>>>> {
        let class_at = |re: &Option<regex::Regex>, c: Option<char>| match (re, c) {
            (Some(re), Some(c)) => re.is_match(c.encode_utf8(&mut [0; 4])),
            _ => false,
        };
        let starts: Vec<usize> = if search {
            subject
                .char_indices()
                .map(|(i, _)| i)
                .chain([subject.len()])
                .collect()
        } else {
            vec![0]
        };
        for start in starts {
            if class_at(&self.behind, subject[..start].chars().next_back()) {
                continue;
            }
            let Some(c) = self.core.captures(&subject[start..]) else {
                continue;
            };
            let end = start + c.get(0).expect("group 0").end();
            if class_at(&self.ahead, subject[end..].chars().next()) {
                continue;
            }
            return Ok(Some(
                c.iter().map(|g| g.map(|m| Rc::from(m.as_str()))).collect(),
            ));
        }
        Ok(None)
    }
}
