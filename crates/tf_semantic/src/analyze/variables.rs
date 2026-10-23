use super::*;

impl<'a, 'o> Analyzer<'a, 'o> {
    // ---- variables, locals, outputs -------------------------------------

    #[expect(clippy::too_many_lines)]
    pub(super) fn var_value(&self, inst_id: usize, name: &str) -> Value {
        if self.loading_exhausted() {
            return Value::other("module inputs unavailable after loader exhaustion");
        }
        let inst = self.inst(inst_id);
        self.memo(
            &inst.vars,
            name,
            || name.to_string(),
            || format!("var.{name}"),
            || {
                let Some(decl) = inst.def.variable(name) else {
                    return Value::error(format!(
                        "reference to undeclared input variable \"{name}\""
                    ));
                };
                let header = FileSpan::new(decl.file, header_span(decl.block));
                let var_step = |label: String| Step::new(StepKind::Variable, header, label);
                let from_default = || -> Option<Value> {
                    let d = decl.default?;
                    let file = inst.def.origins.file(d, decl.file);
                    let v = decl
                        .default_value
                        .clone()
                        .unwrap_or_else(|| self.eval_const(file, &d.value));
                    Some(v.push(Step::new(
                        StepKind::VariableDefault,
                        FileSpan::new(file, d.span),
                        format!("variable {name} default"),
                    )))
                };
                let v = match inst.parent {
                    None => {
                        if let Some(tb) = self.tfvars.iter().rev().find(|t| t.name == name) {
                            let v = self.eval_const(tb.file.id, &tb.attr.value);
                            let fname = tb
                                .file
                                .path
                                .file_name()
                                .map(|s| s.to_string_lossy().to_string())
                                .unwrap_or_default();
                            v.push(Step::new(
                                StepKind::Tfvars,
                                FileSpan::new(tb.file.id, tb.attr.span),
                                format!("{fname}: {}", snippet(&tb.file.text, tb.attr.span, 60)),
                            ))
                            .push(var_step(format!("variable {name}")))
                        } else if let Some(v) = from_default() {
                            v
                        } else {
                            Value::tainted(name).push(var_step(format!(
                                "variable {name} (no default, no tfvars value: unconstrained)"
                            )))
                        }
                    }
                    Some((pid, ci)) => {
                        let parent = self.inst(pid);
                        let call = &parent.def.module_calls[ci];
                        match call.block.body.find_attribute(name) {
                            Some(arg) => {
                                let file = parent.def.origins.file(arg, call.file);
                                let v = Scope::EMPTY.with_all(inst.binds.as_slice(), |sc| {
                                    self.eval(pid, file, &arg.value, sc)
                                });
                                v.push(Step::new(
                                    StepKind::ModuleArgument,
                                    FileSpan::new(file, arg.span),
                                    format!(
                                        "{}module.{} argument {name}",
                                        parent.prefix(),
                                        call.name
                                    ),
                                ))
                                .push(var_step(format!("variable {name}")))
                            }
                            None => match from_default() {
                                Some(v) => v,
                                None => Value::tainted(name).push(var_step(format!(
                                    "variable {name} (not set by module.{}, no default)",
                                    call.name
                                ))),
                            },
                        }
                    }
                };
                let v = if decl.non_nullable && v.is_null() {
                    from_default().unwrap_or(v)
                } else {
                    v
                };
                // Overrides replace the constraint but retain the original
                // declaration's optional defaults for all runtime inputs.
                let mut v = crate::input_conversion::convert_input(
                    v,
                    decl.ty,
                    inst.def.origins.type_defaults(decl.block),
                    crate::input_conversion::InputContext {
                        budget: &self.budget,
                        at: header,
                    },
                );
                if declared_sensitive(&decl.block.body) {
                    v = v.sensitive();
                }
                self.mark_sensitive(&v);
                v
            },
        )
    }

    pub(super) fn local_value(&self, inst_id: usize, name: &str) -> Value {
        let inst = self.inst(inst_id);
        self.memo(
            &inst.locals,
            name,
            || name.to_string(),
            || format!("local.{name}"),
            || {
                let Some(decl) = inst.def.local(name) else {
                    return Value::error(format!("reference to undeclared local value \"{name}\""));
                };
                let v = self.eval(inst_id, decl.file, &decl.attr.value, Scope::EMPTY);
                let v = v.push(Step::new(
                    StepKind::Local,
                    FileSpan::new(decl.file, decl.attr.span),
                    format!("local.{name}"),
                ));
                self.mark_sensitive(&v);
                v
            },
        )
    }

    pub(super) fn output_value(&self, inst_id: usize, name: &str) -> Value {
        let inst = self.inst(inst_id);
        self.memo(
            &inst.outputs,
            name,
            || name.to_string(),
            || format!("output {name}"),
            || {
                let Some(decl) = inst.def.output(name) else {
                    return Value::error(format!("module has no output \"{name}\""));
                };
                let Some(va) = decl.value else {
                    return Value::error("output without value");
                };
                let file = inst.def.origins.file(va, decl.file);
                let mut v = self.eval(inst_id, file, &va.value, Scope::EMPTY);
                if declared_sensitive(&decl.block.body) {
                    v = v.sensitive();
                }
                if v.is_sensitive() {
                    self.files.mark_sensitive(FileSpan::new(file, va.span));
                    self.mark_sensitive(&v);
                }
                v.push(Step::new(
                    StepKind::Output,
                    FileSpan::new(file, va.span),
                    format!(
                        "{}output {name}",
                        if inst.address.is_empty() {
                            String::new()
                        } else {
                            format!("{} ", inst.address)
                        }
                    ),
                ))
            },
        )
    }
}
