use super::*;

impl<'p> Interp<'p> {
    // -- statements ------------------------------------------------------

    pub(super) fn block(&mut self, stmts: &[Stmt], env: &mut Env) -> R<()> {
        for s in stmts {
            self.stmt(s, env)?;
        }
        Ok(())
    }

    #[expect(clippy::too_many_lines)]
    pub(super) fn stmt(&mut self, s: &Stmt, env: &mut Env) -> R<()> {
        self.step()?;
        match s {
            Stmt::Expr { value } => {
                self.expr(value, env)?;
            }
            Stmt::Return { value } => {
                let v = match value {
                    Some(e) => self.expr(e, env)?,
                    None => Py::None,
                };
                return Err(Flow::Return(v));
            }
            Stmt::If { test, body, orelse } => {
                let t = self.expr(test, env)?;
                if self.truthy(&t)? {
                    self.block(body, env)?;
                } else {
                    self.block(orelse, env)?;
                }
            }
            Stmt::For {
                target,
                iter,
                body,
                orelse,
            } => {
                let it = self.expr(iter, env)?;
                let items = self.iterate(&it)?;
                let mut broke = false;
                for item in items {
                    self.assign(target, item, env)?;
                    match self.block(body, env) {
                        Ok(()) | Err(Flow::Continue) => {}
                        Err(Flow::Break) => {
                            broke = true;
                            break;
                        }
                        Err(f) => return Err(f),
                    }
                }
                if !broke {
                    self.block(orelse, env)?;
                }
            }
            Stmt::Assign { targets, value } => {
                let v = self.expr(value, env)?;
                for t in targets {
                    self.assign(t, v.clone(), env)?;
                }
            }
            Stmt::Aug { target, op, value } => {
                let current = match target {
                    Target::Name { id } => self.lookup(id, env)?,
                    Target::SelfAttr { attr } => self.self_attr(attr)?,
                    Target::Attr { value, attr } => {
                        let obj = self.expr(value, env)?;
                        self.get_attr(&obj, attr)?
                    }
                    Target::Sub { value, index } => {
                        let (c, i) = (self.expr(value, env)?, self.expr(index, env)?);
                        self.subscript(&c, &i)?
                    }
                    Target::Tuple { .. } => return unsupported("augmented tuple assignment"),
                };
                let rhs = self.expr(value, env)?;
                let v = self.binop(*op, &current, &rhs, true)?;
                self.assign(target, v, env)?;
            }
            Stmt::Pass => {}
            Stmt::Break => return Err(Flow::Break),
            Stmt::Continue => return Err(Flow::Continue),
            Stmt::Try {
                body,
                handlers,
                orelse,
                finalbody,
            } => {
                let outcome = match self.block(body, env) {
                    Ok(()) => self.block(orelse, env),
                    Err(Flow::Exc(raised)) => {
                        if debug() == "3" {
                            eprintln!("caught {raised}");
                        }
                        let handler = handlers.iter().find(|h| {
                            h.types
                                .as_ref()
                                .is_none_or(|ts| ts.iter().any(|t| catches(t, &raised)))
                        });
                        match handler {
                            Some(h) => {
                                if let Some(n) = &h.name {
                                    env.insert(n.clone(), Py::Exception(raised.clone()));
                                }
                                self.block(&h.body, env)
                            }
                            None => Err(Flow::Exc(raised)),
                        }
                    }
                    Err(f) => Err(f),
                };
                // `finally` runs on every exit; its own exit wins.
                if !finalbody.is_empty() {
                    match outcome {
                        Err(f @ (Flow::Abstract(..) | Flow::Fork(..) | Flow::Unsupported(_))) => {
                            return Err(f);
                        }
                        other => {
                            self.block(finalbody, env)?;
                            return other;
                        }
                    }
                }
                return outcome;
            }
            Stmt::Raise { ty } => {
                return Err(Flow::Exc(Rc::from(ty.as_deref().unwrap_or("Exception"))));
            }
        }
        Ok(())
    }

    pub(super) fn assign(&mut self, t: &Target, v: Py, env: &mut Env) -> R<()> {
        match t {
            Target::Name { id } => {
                env.insert(id.clone(), v);
            }
            Target::SelfAttr { attr } => {
                self.self_attrs.insert(attr.clone(), v);
            }
            Target::Attr { value, attr } => match self.expr(value, env)? {
                Py::Instance(i) => {
                    i.attrs.borrow_mut().insert(attr.clone(), v);
                }
                _ => return exc("AttributeError"),
            },
            Target::Tuple { elts } => {
                let items = self.iterate(&v)?;
                if items.len() != elts.len() {
                    return exc("ValueError");
                }
                for (t, item) in elts.iter().zip(items) {
                    self.assign(t, item, env)?;
                }
            }
            Target::Sub { value, index } => {
                let container = self.expr(value, env)?;
                let index = self.expr(index, env)?;
                match self.concrete(&container)? {
                    Py::List(l) => {
                        let i = self.index_of(&index, l.borrow().len())?;
                        l.borrow_mut()[i] = v;
                    }
                    Py::Dict(d) => {
                        let key = self.concrete(&index)?;
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
                            Some(i) => d.borrow_mut()[i].1 = v,
                            None => d.borrow_mut().push((key, v)),
                        }
                    }
                    _ => return exc("TypeError"),
                }
            }
        }
        Ok(())
    }

    pub(super) fn lookup(&self, id: &str, env: &Env) -> R<Py> {
        match env.get(id) {
            Some(v) => Ok(v.clone()),
            None => exc("NameError"),
        }
    }

    pub(super) fn self_attr(&self, attr: &str) -> R<Py> {
        match self.self_attrs.get(attr) {
            Some(v) => Ok(v.clone()),
            None => exc("AttributeError"),
        }
    }

    /// The elements `for x in v` visits.
    pub(super) fn iterate(&self, v: &Py) -> R<Vec<Py>> {
        match v {
            Py::Data(Json::Object(m)) => return Ok(m.keys().map(|k| Py::str(k)).collect()),
            Py::Data(Json::Array(a)) => return Ok(a.iter().map(data_child).collect()),
            _ => {}
        }
        Ok(match self.concrete(v)? {
            Py::List(l) | Py::Set(l) => l.borrow().clone(),
            Py::Tuple(t) => t.to_vec(),
            Py::Dict(d) => d.borrow().iter().map(|(k, _)| k.clone()).collect(),
            Py::Str(s) => s
                .chars()
                .map(|c| Py::str(c.encode_utf8(&mut [0; 4])))
                .collect(),
            Py::Range(a, b, s) => range_items(a, b, s).into_iter().map(Py::Int).collect(),
            _ => return exc("TypeError"),
        })
    }

    pub(super) fn index_of(&self, index: &Py, len: usize) -> R<usize> {
        let i = match self.concrete(index)? {
            Py::Int(i) => i,
            Py::Bool(b) => b as i64,
            _ => return exc("TypeError"),
        };
        let i = if i < 0 { i + len as i64 } else { i };
        if i < 0 || i >= len as i64 {
            return exc("IndexError");
        }
        Ok(i as usize)
    }

    pub(super) fn subscript(&self, container: &Py, index: &Py) -> R<Py> {
        match container {
            Py::Data(Json::Object(m)) => {
                return match self.concrete(index)? {
                    Py::Str(k) => m
                        .get(&*k)
                        .map(data_child)
                        .map_or_else(|| exc("KeyError"), Ok),
                    _ => exc("KeyError"),
                };
            }
            Py::Data(Json::Array(a)) => {
                let i = self.index_of(index, a.len())?;
                return Ok(data_child(&a[i]));
            }
            _ => {}
        }
        match self.concrete(container)? {
            Py::List(l) => {
                let items = l.borrow();
                let i = self.index_of(index, items.len())?;
                Ok(items[i].clone())
            }
            Py::Tuple(t) => {
                let i = self.index_of(index, t.len())?;
                Ok(t[i].clone())
            }
            Py::Str(s) => {
                let chars: Vec<char> = s.chars().collect();
                let i = self.index_of(index, chars.len())?;
                Ok(Py::str(chars[i].encode_utf8(&mut [0; 4])))
            }
            Py::Dict(d) => {
                let found = self.dict_get(&d.borrow(), index)?;
                self.note(&d, &self.concrete(index)?, found.is_some());
                found.map_or_else(|| exc("KeyError"), Ok)
            }
            Py::Match(groups) => {
                let i = self.index_of(index, groups.len())?;
                Ok(groups[i].as_deref().map_or(Py::None, Py::str))
            }
            _ => exc("TypeError"),
        }
    }

    // -- expressions -----------------------------------------------------
}
