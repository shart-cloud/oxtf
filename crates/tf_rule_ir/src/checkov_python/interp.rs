use super::*;

// -- control flow ---------------------------------------------------------

pub(super) enum Flow {
    Return(Py),
    Break,
    Continue,
    /// A Python exception, by class name.
    Exc(Rc<str>),
    /// An abstract value decided the run.
    Abstract(Rc<Value>, bool),
    /// A `OneOf` (by id, with its number of alternatives) must be resolved.
    Fork(usize, usize),
    /// Outside the interpreted subset, or the step budget ran out.
    Unsupported(String),
}

pub(super) type R<T> = Result<T, Flow>;

/// `OXTF_DEBUG_PYTHON`, read once: `1` logs failures, `2` every outcome,
/// `3` exceptions as raised and caught, `time` each run's duration.
pub(super) fn debug() -> &'static str {
    static LEVEL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    LEVEL.get_or_init(|| std::env::var("OXTF_DEBUG_PYTHON").unwrap_or_default())
}

#[track_caller]
pub(super) fn exc<T>(name: &str) -> R<T> {
    if debug() == "3" {
        eprintln!("raise {name} at {}", std::panic::Location::caller());
    }
    Err(Flow::Exc(Rc::from(name)))
}

pub(super) fn unsupported<T>(what: impl Into<String>) -> R<T> {
    Err(Flow::Unsupported(what.into()))
}

/// Whether an exception of class `raised` is caught by `handler`.
pub(super) fn catches(handler: &str, raised: &str) -> bool {
    let parents: &[&str] = match raised {
        "KeyError" | "IndexError" => &["LookupError"],
        "JSONDecodeError" => &["ValueError"],
        "ZeroDivisionError" => &["ArithmeticError"],
        _ => &[],
    };
    handler == raised || handler == "Exception" || parents.contains(&handler)
}

// -- the interpreter -------------------------------------------------------

pub(super) struct Interp<'p> {
    pub(super) program: &'p Program,
    pub(super) resource: &'p Resource,
    pub(super) self_attrs: HashMap<String, Py>,
    /// The alternative chosen for each `OneOf` resolved so far.
    pub(super) choices: HashMap<usize, usize>,
    /// Mutable module and class attributes ([`Expr::Static`]) this run.
    pub(super) statics: HashMap<String, Py>,
    /// Statements, expressions and copied data nodes so far this run.
    pub(super) steps: std::cell::Cell<u32>,
    pub(super) budget: &'p RuleBudget,
    /// Where the configuration's dicts sit in it.
    pub(super) paths: Rc<Paths>,
    /// Configuration lookups so far this run, in order.
    pub(super) reads: RefCell<Vec<Read>>,
    /// `conf.keys()` lists of configuration dicts, by the list's address,
    /// so `"k" in conf.keys()` is traced like `"k" in conf`. The list is
    /// held so its address is not reused this run.
    pub(super) key_lists: RefCell<HashMap<usize, (List, ConfPath)>>,
    /// The witness of the last native check the program delegated to
    /// (Checkov's generic value check): it located what it judged.
    pub(super) delegated: RefCell<Option<Value>>,
}

pub(super) type Env = HashMap<String, Py>;

impl<'p> Interp<'p> {
    pub(super) fn step(&mut self) -> R<()> {
        self.charge(1)
    }

    pub(super) fn charge(&self, steps: u64) -> R<()> {
        let used = self.steps.get();
        assert!(used <= STEP_BUDGET);
        if steps > u64::from(STEP_BUDGET - used) {
            return unsupported("step budget exhausted");
        }
        self.budget.charge(steps).map_err(Flow::Unsupported)?;
        self.steps.set(used + steps as u32);
        assert!(self.steps.get() <= STEP_BUDGET);
        Ok(())
    }

    pub(super) fn charge_data(&self, data: &Json) -> R<()> {
        self.charge(1)?;
        let mut pending = vec![data];
        while let Some(node) = pending.pop() {
            match node {
                Json::Array(items) => {
                    self.charge(items.len() as u64)?;
                    pending.extend(items);
                }
                Json::Object(items) => {
                    self.charge(items.len() as u64)?;
                    pending.extend(items.values());
                }
                _ => {}
            }
            assert!(pending.len() <= STEP_BUDGET as usize);
        }
        Ok(())
    }

    /// `v` with abstractions resolved, or the flow they demand.
    /// Trace a lookup of `key` in `dict` when the dict is part of the
    /// resource's configuration.
    pub(super) fn note(&self, dict: &Rc<RefCell<Vec<(Py, Py)>>>, key: &Py, present: bool) {
        let addr = Rc::as_ptr(dict) as *const () as usize;
        if let (Some(path), Py::Str(k)) = (self.paths.get(&addr), key) {
            self.reads.borrow_mut().push(Read {
                dict: path.clone(),
                key: k.clone(),
                present,
            });
        }
    }

    pub(super) fn concrete(&self, v: &Py) -> R<Py> {
        match v {
            Py::Abstract(w, tainted) => Err(Flow::Abstract(w.clone(), *tainted)),
            // Operations without an in-place form read a copy, which counts
            // against the step budget like the work it is.
            Py::Data(j) => {
                self.charge_data(j)?;
                Ok(json_to_py(j))
            }
            Py::OneOf(id, alts) => match self.choices.get(id) {
                Some(&i) => self.concrete(&alts[i]),
                None => Err(Flow::Fork(*id, alts.len())),
            },
            other => Ok(other.clone()),
        }
    }

    pub(super) fn truthy(&self, v: &Py) -> R<bool> {
        if let Py::Data(j) = v {
            return Ok(match j {
                Json::Object(m) => !m.is_empty(),
                Json::Array(a) => !a.is_empty(),
                _ => true,
            });
        }
        Ok(match self.concrete(v)? {
            Py::None => false,
            Py::Bool(b) => b,
            Py::Int(i) => i != 0,
            Py::Float(f) => f != 0.0,
            Py::Str(s) => !s.is_empty(),
            Py::List(l) | Py::Set(l) => !l.borrow().is_empty(),
            Py::Tuple(t) => !t.is_empty(),
            Py::Dict(d) => !d.borrow().is_empty(),
            Py::Range(a, b, s) => range_len(a, b, s) > 0,
            _ => true,
        })
    }

    pub(super) fn eq(&self, a: &Py, b: &Py) -> R<bool> {
        let (a, b) = (self.concrete(a)?, self.concrete(b)?);
        Ok(match (&a, &b) {
            (Py::None, Py::None) => true,
            (Py::Str(x), Py::Str(y)) => x == y,
            (Py::Result(x), Py::Result(y)) | (Py::Type(x), Py::Type(y)) => x == y,
            (Py::List(x), Py::List(y)) => {
                if Rc::ptr_eq(x, y) {
                    return Ok(true);
                }
                let (x, y) = (x.borrow().clone(), y.borrow().clone());
                self.seq_eq(&x, &y)?
            }
            (Py::Tuple(x), Py::Tuple(y)) => self.seq_eq(x, y)?,
            (Py::Set(x), Py::Set(y)) => {
                let (x, y) = (x.borrow().clone(), y.borrow().clone());
                x.len() == y.len() && self.all_in(&x, &y)?
            }
            (Py::Dict(x), Py::Dict(y)) => {
                let (x, y) = (x.borrow().clone(), y.borrow().clone());
                if x.len() != y.len() {
                    return Ok(false);
                }
                for (k, v) in &x {
                    match self.dict_get(&y, k)? {
                        Some(w) if self.eq(v, &w)? => {}
                        _ => return Ok(false),
                    }
                }
                true
            }
            (Py::Range(a1, b1, s1), Py::Range(a2, b2, s2)) => (a1, b1, s1) == (a2, b2, s2),
            (Py::Instance(x), Py::Instance(y)) => Rc::ptr_eq(x, y),
            (Py::Net(x, a), Py::Net(y, b)) => x == y && a == b,
            _ => match (number(&a), number(&b)) {
                (Some(x), Some(y)) => x == y,
                _ => false,
            },
        })
    }

    pub(super) fn seq_eq(&self, x: &[Py], y: &[Py]) -> R<bool> {
        if x.len() != y.len() {
            return Ok(false);
        }
        for (a, b) in x.iter().zip(y) {
            if !self.eq(a, b)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) fn all_in(&self, x: &[Py], y: &[Py]) -> R<bool> {
        let members = Members::of(y);
        for a in x {
            if !self.member(&members, y, a)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// `needle in items`, with `members` built from `items`.
    pub(super) fn member(&self, members: &Members, items: &[Py], needle: &Py) -> R<bool> {
        match key(needle) {
            Some(k) if members.keys.contains(&k) => Ok(true),
            // A hashable needle equals no other hashable item; only the
            // unhashed ones (abstract values) remain to compare.
            Some(_) => self.contains_seq(&members.rest, needle),
            None => self.contains_seq(items, needle),
        }
    }

    /// `needle in items`: true as soon as a concrete element equals it;
    /// an abstract element only matters when nothing concrete matched.
    pub(super) fn contains_seq(&self, items: &[Py], needle: &Py) -> R<bool> {
        let mut pending = None;
        for item in items {
            match self.eq(item, needle) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(f @ (Flow::Abstract(..) | Flow::Fork(..))) => {
                    pending.get_or_insert(f);
                }
                Err(f) => return Err(f),
            }
        }
        match pending {
            Some(f) => Err(f),
            None => Ok(false),
        }
    }

    pub(super) fn dict_get(&self, items: &[(Py, Py)], key: &Py) -> R<Option<Py>> {
        let key = self.concrete(key)?;
        for (k, v) in items {
            if self.eq(k, &key)? {
                return Ok(Some(v.clone()));
            }
        }
        Ok(None)
    }

    pub(super) fn contains(&self, container: &Py, needle: &Py) -> R<bool> {
        if let Py::Data(Json::Object(m)) = container {
            return match self.concrete(needle)? {
                Py::Str(k) => Ok(m.contains_key(&*k)),
                _ => Ok(false),
            };
        }
        match self.concrete(container)? {
            Py::Str(s) => match self.concrete(needle)? {
                Py::Str(n) => Ok(s.contains(&*n)),
                _ => exc("TypeError"),
            },
            Py::List(l) | Py::Set(l) => {
                let items = l.borrow().clone();
                let found = self.contains_seq(&items, needle)?;
                let addr = Rc::as_ptr(&l) as *const () as usize;
                let dict = self.key_lists.borrow().get(&addr).map(|(_, p)| p.clone());
                if let (Some(dict), Py::Str(key)) = (dict, self.concrete(needle)?) {
                    self.reads.borrow_mut().push(Read {
                        dict,
                        key,
                        present: found,
                    });
                }
                Ok(found)
            }
            Py::Tuple(t) => self.contains_seq(&t, needle),
            Py::Dict(d) => {
                let keys: Vec<Py> = d.borrow().iter().map(|(k, _)| k.clone()).collect();
                let found = self.contains_seq(&keys, needle)?;
                self.note(&d, &self.concrete(needle)?, found);
                Ok(found)
            }
            Py::Range(a, b, s) => match self.concrete(needle)? {
                Py::Int(i) => Ok(range_items(a, b, s).contains(&i)),
                _ => Ok(false),
            },
            Py::Net(net, false) => match self.concrete(needle)? {
                Py::Net(addr, true) => Ok(addr.subnet_of(&net)),
                _ => Ok(false),
            },
            _ => exc("TypeError"),
        }
    }

    pub(super) fn order(&self, a: &Py, b: &Py) -> R<std::cmp::Ordering> {
        let (a, b) = (self.concrete(a)?, self.concrete(b)?);
        if let (Some(x), Some(y)) = (number(&a), number(&b)) {
            return x.partial_cmp(&y).map_or_else(|| exc("ValueError"), Ok);
        }
        match (&a, &b) {
            (Py::Str(x), Py::Str(y)) => Ok(x.cmp(y)),
            (Py::List(x), Py::List(y)) => {
                let (x, y) = (x.borrow().clone(), y.borrow().clone());
                self.seq_order(&x, &y)
            }
            (Py::Tuple(x), Py::Tuple(y)) => self.seq_order(x, y),
            _ => exc("TypeError"),
        }
    }

    pub(super) fn seq_order(&self, x: &[Py], y: &[Py]) -> R<std::cmp::Ordering> {
        for (a, b) in x.iter().zip(y) {
            if !self.eq(a, b)? {
                return self.order(a, b);
            }
        }
        Ok(x.len().cmp(&y.len()))
    }

    pub(super) fn compare(&self, op: CmpOp, a: &Py, b: &Py) -> R<bool> {
        use std::cmp::Ordering::*;
        Ok(match op {
            CmpOp::Eq => self.eq(a, b)?,
            CmpOp::Ne => !self.eq(a, b)?,
            CmpOp::Lt => self.order(a, b)? == Less,
            CmpOp::Le => self.order(a, b)? != Greater,
            CmpOp::Gt => self.order(a, b)? == Greater,
            CmpOp::Ge => self.order(a, b)? != Less,
            CmpOp::In => self.contains(b, a)?,
            CmpOp::NotIn => !self.contains(b, a)?,
            CmpOp::Is => self.is(a, b)?,
            CmpOp::IsNot => !self.is(a, b)?,
        })
    }

    pub(super) fn is(&self, a: &Py, b: &Py) -> R<bool> {
        let (a, b) = (self.concrete(a)?, self.concrete(b)?);
        Ok(match (&a, &b) {
            (Py::None, Py::None) => true,
            (Py::Bool(x), Py::Bool(y)) => x == y,
            (Py::Result(x), Py::Result(y)) | (Py::Type(x), Py::Type(y)) => x == y,
            (Py::List(x), Py::List(y)) | (Py::Set(x), Py::Set(y)) => Rc::ptr_eq(x, y),
            (Py::Dict(x), Py::Dict(y)) => Rc::ptr_eq(x, y),
            (Py::Tuple(x), Py::Tuple(y)) => Rc::ptr_eq(x, y),
            // Small ints and strings are interned by CPython; the checks
            // only compare with None, True and False.
            (Py::Int(x), Py::Int(y)) => x == y && (-5..=256).contains(x),
            _ => false,
        })
    }
}
