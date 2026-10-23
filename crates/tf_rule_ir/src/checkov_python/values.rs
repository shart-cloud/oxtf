use super::*;

// -- runtime values -------------------------------------------------------

pub(super) type List = Rc<RefCell<Vec<Py>>>;

/// A path into a resource's configuration: keys, and `[i]` for list
/// elements (Checkov's `evaluated_keys` spelling, split at `/`).
pub(super) type ConfPath = Rc<[Rc<str>]>;

/// Where each dict of a resource's configuration sits in it, by the
/// dict's address, so a lookup on it can be traced back to an attribute.
pub(super) type Paths = HashMap<usize, ConfPath>;

/// A key a check looked up in a dict of the resource's configuration,
/// and whether it was there. The reads of a failing run say which
/// attribute decided it when the check reports no `evaluated_keys`.
#[derive(Clone, Debug)]
pub(super) struct Read {
    pub(super) dict: ConfPath,
    pub(super) key: Rc<str>,
    pub(super) present: bool,
}

#[derive(Clone)]
pub(super) enum Py {
    None,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Rc<str>),
    List(List),
    Tuple(Rc<Vec<Py>>),
    Set(List),
    Dict(Rc<RefCell<Vec<(Py, Py)>>>),
    Range(i64, i64, i64),
    /// A `CheckResult` member.
    Result(Rc<str>),
    /// A type object (`isinstance`'s second argument).
    Type(Rc<str>),
    Pattern(Rc<str>),
    Match(Rc<Vec<Option<Rc<str>>>>),
    Lambda(Rc<(Vec<String>, Expr)>),
    /// A program function used as a value (`map(self.f, xs)`).
    FuncRef(Rc<str>),
    /// A built-in used as a value (`map(str, xs)`, `key=len`).
    Builtin(Rc<str>),
    /// An object of an inlined class.
    Instance(Rc<Instance>),
    /// A read-only dict or list of bundled data (policy_sentry's IAM
    /// database), read in place.
    Data(&'static Json),
    /// `ipaddress.ip_network` / `ip_address` (an address is a network of
    /// one; `in` tests containment).
    Net(py::Network, bool),
    /// A method of an object, not yet called.
    Bound(Rc<(Py, Rc<str>)>),
    Exception(Rc<str>),
    /// An abstract configured value (Unknown / Tainted).
    Abstract(Rc<Value>, bool),
    /// A `OneOf`, by id, with its alternatives.
    OneOf(usize, Rc<Vec<Py>>),
}

impl Py {
    pub(super) fn str(s: &str) -> Py {
        Py::Str(Rc::from(s))
    }
    pub(super) fn list(v: Vec<Py>) -> Py {
        Py::List(Rc::new(RefCell::new(v)))
    }
    pub(super) fn tuple(v: Vec<Py>) -> Py {
        Py::Tuple(Rc::new(v))
    }

    /// A program constant (`checkov_python.py` tagged form).
    #[expect(clippy::too_many_lines)]
    pub(super) fn from_const(v: &Json) -> Result<Py, String> {
        Ok(match v {
            Json::Null => Py::None,
            Json::Bool(b) => Py::Bool(*b),
            Json::Number(n) => match n.as_i64() {
                Some(i) if !n.is_f64() => Py::Int(i),
                _ => Py::Float(n.as_f64().ok_or("number out of range")?),
            },
            Json::String(s) => Py::str(s),
            Json::Object(m) if m.len() == 1 => {
                let (tag, inner) = m.iter().next().expect("one entry");
                let items = |inner: &Json| -> Result<Vec<Py>, String> {
                    inner
                        .as_array()
                        .ok_or("tagged container is not an array")?
                        .iter()
                        .map(Py::from_const)
                        .collect()
                };
                match tag.as_str() {
                    "list" => Py::list(items(inner)?),
                    "tuple" => Py::tuple(items(inner)?),
                    "set" => Py::Set(Rc::new(RefCell::new(items(inner)?))),
                    "dict" => {
                        let mut out = Vec::new();
                        for pair in inner.as_array().ok_or("dict is not an array")? {
                            let [k, v] = pair.as_array().map(Vec::as_slice).unwrap_or(&[]) else {
                                return Err("dict entry is not a pair".into());
                            };
                            out.push((Py::from_const(k)?, Py::from_const(v)?));
                        }
                        Py::Dict(Rc::new(RefCell::new(out)))
                    }
                    "result" => Py::Result(Rc::from(inner.as_str().ok_or("result")?)),
                    // A plain enum member, equal only to itself: kept as a
                    // result-like constant under its qualified name.
                    "enum" => Py::Result(Rc::from(inner.as_str().ok_or("enum")?)),
                    "funcref" => Py::FuncRef(Rc::from(inner.as_str().ok_or("funcref")?)),
                    // An inlined class, as `isinstance`'s second argument.
                    "classtype" => Py::Type(Rc::from(format!(
                        "class:{}",
                        inner.as_str().ok_or("classtype")?
                    ))),
                    "iam" => Py::Data(iam::definition()?),
                    "object" => {
                        let class = inner["class"].as_str().ok_or("object class")?;
                        let mut attrs = HashMap::default();
                        for (k, v) in inner["attrs"].as_object().ok_or("object attrs")? {
                            attrs.insert(k.clone(), Py::from_const(v)?);
                        }
                        Py::Instance(Rc::new(Instance {
                            class: Rc::from(class),
                            attrs: RefCell::new(attrs),
                        }))
                    }
                    "builtin" => Py::Builtin(Rc::from(inner.as_str().ok_or("builtin")?)),
                    "type" => Py::Type(Rc::from(inner.as_str().ok_or("type")?)),
                    "pattern" => {
                        let p = inner.as_str().ok_or("pattern")?;
                        check_pattern(p)?;
                        Py::Pattern(Rc::from(p))
                    }
                    "range" => {
                        let r: Vec<i64> = inner
                            .as_array()
                            .ok_or("range")?
                            .iter()
                            .map(|x| x.as_i64().ok_or("range bound"))
                            .collect::<Result<_, _>>()?;
                        let [a, b, s] = r[..] else {
                            return Err("range".into());
                        };
                        Py::Range(a, b, s)
                    }
                    other => return Err(format!("unknown constant tag {other:?}")),
                }
            }
            other => return Err(format!("untagged constant {other}")),
        })
    }

    pub(super) fn type_name(&self) -> &'static str {
        match self {
            Py::None => "NoneType",
            Py::Bool(_) => "bool",
            Py::Int(_) => "int",
            Py::Float(_) => "float",
            Py::Str(_) => "str",
            Py::List(_) => "list",
            Py::Tuple(_) => "tuple",
            Py::Set(_) => "set",
            Py::Dict(_) => "dict",
            Py::Range(..) => "range",
            Py::Result(_) => "CheckResult",
            Py::Type(_) => "type",
            Py::Pattern(_) => "Pattern",
            Py::Match(_) => "Match",
            Py::Lambda(_) | Py::FuncRef(_) => "function",
            Py::Builtin(_) => "builtin_function_or_method",
            Py::Instance(_) => "object",
            Py::Data(Json::Object(_)) => "dict",
            Py::Data(_) => "list",
            Py::Net(_, true) => "IPv4Address",
            Py::Net(..) => "IPv4Network",
            Py::Bound(_) => "method",
            Py::Exception(_) => "type",
            Py::Abstract(..) | Py::OneOf(..) => "abstract",
        }
    }
}

pub(super) struct Instance {
    pub(super) class: Rc<str>,
    pub(super) attrs: RefCell<HashMap<String, Py>>,
}

/// A hashable value's identity under Python's `==`: `1`, `1.0` and
/// `True` are one key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) enum Key {
    None,
    Int(i64),
    Float(u64),
    Str(Rc<str>),
    Tuple(Vec<Key>),
    Name(Rc<str>),
}

pub(super) fn key(v: &Py) -> Option<Key> {
    Some(match v {
        Py::None => Key::None,
        Py::Bool(b) => Key::Int(*b as i64),
        Py::Int(i) => Key::Int(*i),
        Py::Float(f) if f.is_nan() => return None,
        Py::Float(f) if f.fract() == 0.0 && f.abs() < 9.0e18 => Key::Int(*f as i64),
        Py::Float(f) => Key::Float(f.to_bits()),
        Py::Str(s) => Key::Str(s.clone()),
        Py::Tuple(t) => Key::Tuple(t.iter().map(key).collect::<Option<_>>()?),
        Py::Result(n) | Py::Type(n) => Key::Name(n.clone()),
        _ => return None,
    })
}

/// A dict being built: hashable keys are indexed, so a comprehension over
/// many items is linear, as in Python.
#[derive(Default)]
pub(super) struct DictBuilder {
    pub(super) entries: Vec<(Py, Py)>,
    pub(super) index: HashMap<Key, usize>,
    pub(super) unhashed: bool,
}

impl DictBuilder {
    pub(super) fn insert(&mut self, interp: &Interp, k: Py, v: Py) -> R<()> {
        let k = interp.concrete(&k)?;
        match key(&k) {
            Some(h) if !self.unhashed => {
                match self.index.get(&h) {
                    Some(&i) => self.entries[i].1 = v,
                    None => {
                        self.index.insert(h, self.entries.len());
                        self.entries.push((k, v));
                    }
                }
                Ok(())
            }
            _ => {
                self.unhashed = true;
                interp.dict_insert(&mut self.entries, k, v)
            }
        }
    }
}

/// The members of a collection, for `in` tests: hashed where Python would
/// hash them; anything else (an abstract value) is compared one by one.
pub(super) struct Members {
    pub(super) keys: std::collections::HashSet<Key>,
    pub(super) rest: Vec<Py>,
}

impl Members {
    pub(super) fn of(items: &[Py]) -> Members {
        let mut keys = std::collections::HashSet::new();
        let mut rest = Vec::new();
        for item in items {
            match key(item) {
                Some(k) => {
                    keys.insert(k);
                }
                None => rest.push(item.clone()),
            }
        }
        Members { keys, rest }
    }

    pub(super) fn insert(&mut self, item: &Py) {
        match key(item) {
            Some(k) => {
                self.keys.insert(k);
            }
            None => self.rest.push(item.clone()),
        }
    }
}
