use super::*;

impl<'a, 'o> Analyzer<'a, 'o> {
    fn expand(
        &self,
        inst_id: usize,
        file: FileId,
        body: &'a Body<'a>,
        sc: Scope<'_>,
    ) -> Build<Expansion> {
        let (mut binds, count, each) = self.expand_inner(inst_id, file, body, sc)?;
        let limited = binds.len() > self.opts.max_instances.saturating_sub(self.expanded.get());
        if limited {
            self.diag(
                DiagSeverity::Warning,
                "coverage-expansion",
                format!(
                    "root exceeds the {} total instance limit",
                    self.opts.max_instances
                ),
                Some(FileSpan::new(file, body.span)),
            );
            binds.clear();
        } else {
            self.expanded.set(self.expanded.get() + binds.len());
        }
        Ok((binds, count, each, limited))
    }

    pub(super) fn expand_inner(
        &self,
        inst_id: usize,
        file: FileId,
        body: &'a Body<'a>,
        sc: Scope<'_>,
    ) -> Build<(Vec<InstBind>, Option<Value>, Option<Value>)> {
        if let Some(c) = body.find_attribute("count") {
            let file = self.inst(inst_id).def.origins.file(c, file);
            let value = self.eval(inst_id, file, &c.value, sc);
            self.report_limits(&value, FileSpan::new(file, c.span));
            let binds = self
                .count_binds(&value, FileSpan::new(file, c.span))
                .map_err(|stopped| failure(stopped, [&value]))?;
            return Ok((binds, Some(value), None));
        }
        if let Some(fe) = body.find_attribute("for_each") {
            let file = self.inst(inst_id).def.origins.file(fe, file);
            let at = FileSpan::new(file, fe.span);
            let value = self.eval(inst_id, file, &fe.value, sc).push(Step::new(
                StepKind::Iteration,
                at,
                "for_each",
            ));
            self.report_limits(&value, at);
            let binds = self
                .each_binds(&value, at)
                .map_err(|stopped| failure(stopped, [&value]))?;
            return Ok((binds, None, Some(value)));
        }
        let binds = collections::collect(
            std::iter::once(InstBind {
                key: None,
                binds: None,
                existence: Truth::True,
            }),
            self.budget.storage(),
        )?;
        Ok((binds, None, None))
    }

    pub(super) fn count_binds(&self, value: &Value, at: FileSpan) -> Build<Vec<InstBind>> {
        let existence = match &value.kind {
            Kind::Known(_) => match value.as_number() {
                Some(n) if n.is_finite() && n >= 0.0 && n.fract() == 0.0 => {
                    if n <= self.opts.max_expand as f64 {
                        return collections::try_collect(
                            (0..n as usize).map(|index| {
                                Ok(InstBind {
                                    key: Some(InstanceKey::Index(index as u64)),
                                    binds: Some((
                                        "count",
                                        self.obj1("index", Value::number(index as f64))?,
                                    )),
                                    existence: Truth::True,
                                })
                            }),
                            self.budget.storage(),
                        );
                    }
                    self.diag(
                        DiagSeverity::Warning,
                        "coverage-count",
                        format!("count exceeds the {} instance limit", self.opts.max_expand),
                        Some(at),
                    );
                    Truth::True
                }
                _ => {
                    self.diag(
                        DiagSeverity::Error,
                        "invalid-count",
                        "count must be a nonnegative whole number".into(),
                        Some(at),
                    );
                    Truth::Unknown
                }
            },
            Kind::Tainted(_) => Truth::Tainted,
            Kind::Unknown(_) => Truth::Unknown,
            Kind::OneOf(o) => {
                if o.alternatives
                    .iter()
                    .all(|a| a.as_number().is_some_and(|n| n <= 0.0))
                {
                    return Ok(Vec::new());
                }
                if o.alternatives
                    .iter()
                    .all(|a| a.as_number().is_some_and(|n| n >= 1.0))
                {
                    Truth::True
                } else {
                    tf_eval::truth::uncertainty(value)
                }
            }
        };
        self.abstract_count(existence)
    }

    fn abstract_count(&self, existence: Truth) -> Build<Vec<InstBind>> {
        collections::try_collect(
            std::iter::once_with(|| {
                Ok(InstBind {
                    key: None,
                    binds: Some((
                        "count",
                        self.obj1(
                            "index",
                            Value::other("count.index (instances not expanded)"),
                        )?,
                    )),
                    existence,
                })
            }),
            self.budget.storage(),
        )
    }

    pub(super) fn each_binds(&self, value: &Value, at: FileSpan) -> Build<Vec<InstBind>> {
        if value.is_sensitive() {
            self.files.mark_sensitive(at);
            self.mark_sensitive(value);
            self.diag(
                DiagSeverity::Error,
                "sensitive-for-each",
                "sensitive values cannot determine resource or module instance keys".into(),
                Some(at),
            );
            let unknown = Value::other("sensitive for_each").sensitive();
            return self.abstract_each(|| self.obj2(unknown.clone(), unknown), Truth::Unknown);
        }
        match collection_items(value) {
            Some(items) if items.len() <= self.opts.max_expand => collections::try_collect(
                items.map(|(key, value)| {
                    let key = key.to_str().unwrap_or_else(|| Arc::from("?"));
                    Ok(InstBind {
                        key: Some(InstanceKey::Key(key.clone())),
                        binds: Some(("each", self.obj2(Value::string(key), value)?)),
                        existence: Truth::True,
                    })
                }),
                self.budget.storage(),
            ),
            Some(_) => {
                self.diag(
                    DiagSeverity::Warning,
                    "coverage-expansion",
                    format!(
                        "for_each exceeds the {} instance limit",
                        self.opts.max_expand
                    ),
                    Some(at),
                );
                let u = Value::other("each (for_each too large to expand)");
                self.abstract_each(|| self.obj2(u.clone(), u), Truth::True)
            }
            None => match (&value.kind, tf_eval::truth::uncertainty(value)) {
                (Kind::Known(Known::Null), _) => Ok(Vec::new()),
                (Kind::Tainted(_), _) => self.abstract_each(|| Ok(value.clone()), Truth::Tainted),
                (_, Truth::Tainted) => self.abstract_each(
                    || Ok(Value::tainted("(conditional for_each)").with_prov(value.prov.clone())),
                    Truth::Tainted,
                ),
                _ => self.abstract_each(
                    || Ok(Value::other("each (for_each not known)").with_prov(value.prov.clone())),
                    Truth::Unknown,
                ),
            },
        }
    }

    fn abstract_each(
        &self,
        build: impl FnOnce() -> Build<Value>,
        existence: Truth,
    ) -> Build<Vec<InstBind>> {
        collections::try_collect(
            std::iter::once_with(|| {
                Ok(InstBind {
                    key: None,
                    binds: Some(("each", build()?)),
                    existence,
                })
            }),
            self.budget.storage(),
        )
    }

    pub(super) fn res_instances(&self, inst_id: usize, ri: usize) -> Build<Rc<Expansion>> {
        collections::admit::<u8>(0, self.budget.storage())?;
        let inst = self.inst(inst_id);
        if let Some(s) = inst.res_insts.borrow().get(&ri) {
            return match s {
                Some(v) => Ok(v.clone()),
                None => {
                    let binds = collections::collect(
                        std::iter::once(InstBind {
                            key: None,
                            binds: None,
                            existence: Truth::Unknown,
                        }),
                        self.budget.storage(),
                    )?;
                    collections::admit::<Expansion>(1, self.budget.storage())?;
                    Ok(Rc::new((binds, None, None, false)))
                }
            };
        }
        storage::hash_slot(&mut inst.res_insts.borrow_mut(), self.budget.storage())?;
        inst.res_insts.borrow_mut().insert(ri, None);
        collections::admit::<Expansion>(1, self.budget.storage())?;
        let decl = &inst.def.resources[ri];
        let r = Rc::new(self.expand(inst_id, decl.file, &decl.block.body, Scope::EMPTY)?);
        *inst.res_insts.borrow_mut().get_mut(&ri).unwrap() = Some(r.clone());
        Ok(r)
    }

    pub(super) fn children_of(&self, inst_id: usize, ci: usize) -> Build<ChildInstances> {
        collections::admit::<u8>(0, self.budget.storage())?;
        let inst = self.inst(inst_id);
        if let Some(s) = inst.children.borrow().get(&ci) {
            return Ok(s.clone().unwrap_or_default());
        }
        storage::hash_slot(&mut inst.children.borrow_mut(), self.budget.storage())?;
        inst.children.borrow_mut().insert(ci, None);
        let call = &inst.def.module_calls[ci];
        let (binds, _, _, limited) =
            self.expand(inst_id, call.file, &call.block.body, Scope::EMPTY)?;
        if limited || self.loading_exhausted() {
            storage::reserve(
                &mut inst.limited_children.borrow_mut(),
                1,
                self.budget.storage(),
            )?;
            inst.limited_children.borrow_mut().push(ci);
        }
        let mut out = Buffer::with_capacity(binds.len(), self.budget.storage())?;
        if !binds.is_empty() && !self.loading_exhausted() {
            let at = FileSpan::new(call.file, header_span(call.block));
            if let Some((dir, package)) = self.child_source(&inst, ci, at)?
                && self.child_available(&inst, ci, &dir, at)
            {
                let def = self.load_def(&dir)?;
                for b in binds {
                    let addr = match &b.key {
                        Some(k) => format!("{}module.{}{}", inst.prefix(), call.name, k),
                        None => format!("{}module.{}", inst.prefix(), call.name),
                    };
                    let key = b.key.clone();
                    let b = InstBind {
                        existence: b.existence.min(inst.existence),
                        ..b
                    };
                    let mut ancestors =
                        Buffer::with_capacity(inst.ancestors.len() + 1, self.budget.storage())?;
                    for ancestor in &inst.ancestors {
                        ancestors.push(ancestor.clone())?;
                    }
                    ancestors.push(dir.clone())?;
                    let id = self.new_instance(
                        def,
                        addr.into(),
                        Some((inst_id, ci)),
                        b,
                        ancestors.finish(),
                        self.copy_package(package.as_ref())?,
                    )?;
                    out.push((key, id))?;
                }
            }
        }
        let rc = Rc::new(out.finish());
        *inst.children.borrow_mut().get_mut(&ci).unwrap() = Some(rc.clone());
        Ok(rc)
    }

    fn child_source(
        &self,
        inst: &Instance<'a>,
        ci: usize,
        at: FileSpan,
    ) -> Build<Option<(PathBuf, Option<InstalledPackage>)>> {
        let call = &inst.def.module_calls[ci];
        let resolved = match &call.source {
            ModuleSource::Local(dir) => {
                let mut package = self.copy_package(inst.package.as_ref())?;
                if let Some(p) = &mut package {
                    storage::reserve(&mut p.calls, 1, self.budget.storage())?;
                    p.calls.push(at);
                    self.files.protect_dir(dir);
                }
                Ok((dir.clone(), package))
            }
            ModuleSource::Remote(_) => {
                let mut calls = Buffer::new(self.budget.storage());
                calls.push(call)?;
                let mut parent = inst.parent;
                while let Some((pid, pci)) = parent {
                    let p = self.inst(pid);
                    calls.push(&p.def.module_calls[pci])?;
                    parent = p.parent;
                }
                calls.reverse();
                self.installed
                    .resolve(&calls)
                    .map(|p| (p.dir.clone(), Some(p)))
            }
            ModuleSource::Invalid => Err("source is missing or not a literal string".into()),
        };
        match resolved {
            Ok(source) => Ok(Some(source)),
            Err(crate::installed::ResolveError::Storage(error)) => {
                Err(Value::limit(error.to_string()))
            }
            Err(crate::installed::ResolveError::Invalid(message)) => {
                self.diag(
                    DiagSeverity::Warning,
                    "coverage-remote-module",
                    format!("module.{}: {message}; source was not evaluated", call.name),
                    Some(at),
                );
                Ok(None)
            }
        }
    }

    fn child_available(&self, inst: &Instance<'a>, ci: usize, dir: &Path, at: FileSpan) -> bool {
        let call = &inst.def.module_calls[ci];
        let canonical = self.files.canonical_path(dir);
        let issue = if inst
            .ancestors
            .iter()
            .any(|p| self.files.canonical_path(p) == canonical)
        {
            Some((
                "module-cycle",
                format!(
                    "module.{} calls an ancestor module ({})",
                    call.name,
                    dir.display()
                ),
            ))
        } else if inst.ancestors.len() > self.opts.max_module_depth {
            Some((
                "module-depth",
                format!(
                    "module.{}: nesting deeper than {}",
                    call.name, self.opts.max_module_depth
                ),
            ))
        } else if !has_module_files(self.files, dir) {
            Some((
                "module-missing",
                format!(
                    "module.{}: no supported .tf files in {}",
                    call.name,
                    dir.display()
                ),
            ))
        } else {
            None
        };
        if let Some((code, message)) = issue {
            self.diag(DiagSeverity::Warning, code, message, Some(at));
            false
        } else {
            true
        }
    }

    pub(super) fn copy_package(
        &self,
        package: Option<&InstalledPackage>,
    ) -> Build<Option<InstalledPackage>> {
        if let Some(package) = package {
            collections::admit::<FileSpan>(package.calls.len(), self.budget.storage())?;
        }
        Ok(package.cloned())
    }
}
