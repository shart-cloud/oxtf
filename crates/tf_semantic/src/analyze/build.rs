use super::*;

impl<'a, 'o> Analyzer<'a, 'o> {
    pub(super) fn build_module(&self, inst_id: usize, module: &mut model::Module) -> Build<()> {
        let inst = self.inst(inst_id);
        let def = inst.def;
        self.build_resources(inst_id, &mut module.resources)?;
        module.variables = collections::collect(
            def.variables.iter().map(|v| model::VariableInfo {
                name: v.name.into(),
                value: self.model_value(
                    self.var_value(inst_id, v.name),
                    FileSpan::new(v.file, header_span(v.block)),
                ),
                span: FileSpan::new(v.file, header_span(v.block)),
            }),
            self.budget.storage(),
        )?;
        module.outputs = collections::collect(
            def.outputs.iter().map(|o| model::VariableInfo {
                name: o.name.into(),
                value: self.model_value(
                    self.output_value(inst_id, o.name),
                    FileSpan::new(o.file, header_span(o.block)),
                ),
                span: FileSpan::new(o.file, header_span(o.block)),
            }),
            self.budget.storage(),
        )?;
        module.module_calls = collections::try_collect(
            def.module_calls
                .iter()
                .map(|call| self.build_call(inst_id, def, call)),
            self.budget.storage(),
        )?;
        module.symbols = self.build_symbols(def)?;
        self.build_block_values(inst_id, module)?;
        module.locals = self.build_locals(inst_id)?;
        collections::admit::<u8>(0, self.budget.storage())?;
        Ok(())
    }

    fn build_resources(&self, inst_id: usize, resources: &mut Vec<model::Resource>) -> Build<()> {
        let inst = self.inst(inst_id);
        let def = inst.def;
        for (ri, decl) in def.resources.iter().enumerate() {
            let insts = self.res_instances(inst_id, ri)?;
            let decl_id = Address::new(inst.address.clone(), decl.mode, decl.ty, decl.name, None);
            let base: Arc<str> = decl_id.base_string().into();
            storage::reserve(resources, insts.0.len(), self.budget.storage())?;
            for b in insts.0.iter() {
                resources.push(self.build_resource(inst_id, decl, b, &insts, &decl_id, &base)?);
            }
        }
        Ok(())
    }

    fn build_resource(
        &self,
        inst_id: usize,
        decl: &ResourceDecl<'a>,
        binding: &InstBind,
        expansion: &Expansion,
        decl_id: &Address,
        base: &Arc<str>,
    ) -> Build<model::Resource> {
        let inst = self.inst(inst_id);
        let def = inst.def;
        let id = decl_id.clone().with_key(binding.key.clone());
        let address: Arc<str> = id.to_string().into();
        let ctx = BodyCtx {
            inst: inst_id,
            file: decl.file,
            origins: &def.origins,
            addr: address.clone(),
            base: base.clone(),
            ty: decl.ty,
            mode: decl.mode,
            strict_bool: decl
                .schema
                .is_some_and(|s| s.provider == tf_schema::Provider::Aws),
            observe: true,
        };
        let body = Scope::EMPTY.with_all(binding.binds.as_slice(), |sc| {
            self.eval_body(
                &ctx,
                &decl.block.body,
                decl.schema.map(|s| s.block()),
                sc,
                "",
                true,
            )
        })?;
        let mut resource = model::Resource::new(
            id,
            FileSpan::new(decl.file, header_span(decl.block)),
            body,
            binding.existence.min(inst.existence),
            expansion.1.clone(),
            expansion.2.clone(),
            decl.schema.map(|s| s.provider),
        );
        if let Some(a) = decl.block.body.find_attribute("depends_on") {
            let file = def.origins.file(a, decl.file);
            let value = Scope::EMPTY.with_all(binding.binds.as_slice(), |sc| {
                self.eval(inst_id, file, &a.value, sc)
            });
            let value = self.model_value(value, FileSpan::new(file, a.span));
            crate::graph::value_dependencies(&value, &mut resource.dependencies);
        }
        collections::admit::<u8>(0, self.budget.storage())?;
        Ok(resource)
    }

    fn build_symbols(&self, def: &ModuleDef<'a>) -> Build<Vec<model::SymbolInfo>> {
        let count = def.variables.len()
            + def.locals.len()
            + def.resources.len()
            + def.module_calls.len()
            + def.outputs.len();
        let mut symbols = Buffer::with_capacity(count, self.budget.storage())?;
        for v in &def.variables {
            symbols.push(model::SymbolInfo {
                symbol: SymbolRef::Variable(v.name.into()),
                span: FileSpan::new(v.file, header_span(v.block)),
            })?;
        }
        for l in &def.locals {
            symbols.push(model::SymbolInfo {
                symbol: SymbolRef::Local(l.name.into()),
                span: FileSpan::new(l.file, l.attr.span),
            })?;
        }
        for r in &def.resources {
            let s = match r.mode {
                Mode::Managed => SymbolRef::Resource(r.ty.into(), r.name.into()),
                Mode::Data => SymbolRef::Data(r.ty.into(), r.name.into()),
            };
            symbols.push(model::SymbolInfo {
                symbol: s,
                span: FileSpan::new(r.file, header_span(r.block)),
            })?;
        }
        for c in &def.module_calls {
            symbols.push(model::SymbolInfo {
                symbol: SymbolRef::Module(c.name.into()),
                span: FileSpan::new(c.file, header_span(c.block)),
            })?;
        }
        for o in &def.outputs {
            symbols.push(model::SymbolInfo {
                symbol: SymbolRef::Output(o.name.into()),
                span: FileSpan::new(o.file, header_span(o.block)),
            })?;
        }
        Ok(symbols.finish())
    }

    fn build_locals(&self, inst_id: usize) -> Build<Vec<model::VariableInfo>> {
        let def = self.inst(inst_id).def;
        // Register sensitive local sources even when no remaining resource
        // refers to them (for example, after a verified edit).
        let mut locals = Buffer::with_capacity(
            if self.opts.whole_files {
                def.locals.len()
            } else {
                0
            },
            self.budget.storage(),
        )?;
        for local in &def.locals {
            let at = FileSpan::new(local.file, local.attr.span);
            let value = self.model_value(self.local_value(inst_id, local.name), at);
            if self.opts.whole_files {
                locals.push(model::VariableInfo {
                    name: local.name.into(),
                    value,
                    span: at,
                })?;
            }
        }
        Ok(locals.finish())
    }

    fn build_block_values(&self, inst_id: usize, module: &mut model::Module) -> Build<()> {
        let def = self.inst(inst_id).def;
        // Every attribute of the other top-level blocks (`provider`,
        // `terraform`, `check`, `import`, ...), evaluated in this instance,
        // by expression span: what a whole-file rule renders.
        let block_values = &mut module.block_values;
        if self.opts.whole_files {
            for (sf, file) in &def.files {
                for b in file.body.blocks() {
                    if !matches!(
                        &*b.ident.name,
                        "resource" | "data" | "module" | "variable" | "locals" | "output"
                    ) {
                        self.block_values(inst_id, sf.id, &b.body, block_values)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn build_call(
        &self,
        inst_id: usize,
        def: &ModuleDef<'a>,
        call: &crate::module::ModuleCall<'a>,
    ) -> Build<model::ModuleCallInfo> {
        let mut arguments = Buffer::new(self.budget.storage());
        if self.opts.whole_files {
            for attr in call.block.body.attributes() {
                if matches!(&*attr.key.name, "providers" | "depends_on") {
                    continue;
                }
                arguments.reserve(1)?;
                let file = def.origins.file(attr, call.file);
                let value = self.model_value(
                    self.eval(inst_id, file, &attr.value, Scope::EMPTY),
                    FileSpan::new(file, attr.span),
                );
                arguments.push((Arc::from(&*attr.key.name), value))?;
            }
        }
        Ok(model::ModuleCallInfo {
            name: call.name.into(),
            source: match &call.source {
                ModuleSource::Local(path) => path.display().to_string(),
                ModuleSource::Remote(source) => source.clone(),
                ModuleSource::Invalid => String::new(),
            },
            remote: matches!(call.source, ModuleSource::Remote(_)),
            span: FileSpan::new(call.file, header_span(call.block)),
            arguments: arguments.finish(),
        })
    }

    fn block_values(
        &self,
        inst_id: usize,
        file: FileId,
        body: &'a Body<'a>,
        out: &mut std::collections::HashMap<FileSpan, Value>,
    ) -> Build<()> {
        for a in body.attributes() {
            storage::hash_slot(out, self.budget.storage())?;
            let file = self.inst(inst_id).def.origins.file(a, file);
            let v = self.eval(inst_id, file, &a.value, Scope::EMPTY);
            let v = self.model_value(v, FileSpan::new(file, a.span));
            out.insert(FileSpan::new(file, tf_span::GetSpan::span(&a.value)), v);
        }
        for b in body.blocks() {
            if &*b.ident.name != "dynamic" {
                self.block_values(inst_id, file, &b.body, out)?;
            }
        }
        Ok(())
    }
}
