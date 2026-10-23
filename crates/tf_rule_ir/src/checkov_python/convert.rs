use super::*;

/// A parsed JSON document as Python's `json.loads` returns it.
pub(super) fn json_to_py(j: &Json) -> Py {
    match j {
        Json::Null => Py::None,
        Json::Bool(b) => Py::Bool(*b),
        Json::Number(n) => match n.as_i64() {
            Some(i) if !n.is_f64() => Py::Int(i),
            _ => Py::Float(n.as_f64().unwrap_or(f64::NAN)),
        },
        Json::String(s) => Py::str(s),
        Json::Array(a) => Py::list(a.iter().map(json_to_py).collect()),
        Json::Object(m) => Py::Dict(Rc::new(RefCell::new(
            m.iter().map(|(k, v)| (Py::str(k), json_to_py(v))).collect(),
        ))),
    }
}

// -- conversion from the configuration -----------------------------------

pub(super) struct Converter {
    pub(super) next_id: usize,
    /// The path of the value being converted.
    pub(super) path: Vec<Rc<str>>,
    pub(super) paths: Paths,
}

impl Converter {
    /// The configured value as Python sees it. Numbers that are integral
    /// are `int`, as Checkov's HCL parser reads them. Every dict's path is
    /// recorded in `paths`.
    pub(super) fn py(&mut self, v: &Value) -> Py {
        match &v.kind {
            Kind::Known(k) => match k {
                Known::Null => Py::None,
                Known::Bool(b) => Py::Bool(*b),
                Known::Number(n) => {
                    if n.fract() == 0.0 && n.abs() < 9.0e15 {
                        Py::Int(*n as i64)
                    } else {
                        Py::Float(*n)
                    }
                }
                Known::String(s) => Py::str(s),
                Known::List(items) => Py::list(
                    items
                        .iter()
                        .enumerate()
                        .map(|(i, x)| self.child(Rc::from(format!("[{i}]")), x))
                        .collect(),
                ),
                Known::Object(m) => {
                    let items = m
                        .iter()
                        .map(|(k, x)| (Py::str(k), self.child(Rc::from(&**k), x)))
                        .collect();
                    let dict = Rc::new(RefCell::new(items));
                    self.paths.insert(
                        Rc::as_ptr(&dict) as *const () as usize,
                        Rc::from(self.path.as_slice()),
                    );
                    Py::Dict(dict)
                }
                Known::Json(inner) => self.py(inner),
            },
            Kind::Unknown(_) => Py::Abstract(Rc::new(v.clone()), false),
            Kind::Tainted(_) => Py::Abstract(Rc::new(v.clone()), true),
            Kind::OneOf(o) => {
                let id = self.next_id;
                self.next_id += 1;
                let alts = o.alternatives.iter().map(|a| self.py(a)).collect();
                Py::OneOf(id, Rc::new(alts))
            }
        }
    }

    pub(super) fn child(&mut self, segment: Rc<str>, v: &Value) -> Py {
        self.path.push(segment);
        let py = self.py(v);
        self.path.pop();
        py
    }
}
