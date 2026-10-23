use super::*;

impl<'a, 'o> Analyzer<'a, 'o> {
    // ---- references -----------------------------------------------------

    #[expect(clippy::too_many_lines)]
    pub(super) fn resource_ref(
        &self,
        inst_id: usize,
        mode: Mode,
        ty: &'a str,
        ops: &'a [TraversalOperator<'a>],
        ev: &Evaluator<'_, 'a>,
        sc: Scope<'_>,
    ) -> Build<(Value, usize)> {
        let inst = self.inst(inst_id);
        let Some(name) = ops.first().and_then(|o| o.attr_name()) else {
            return Ok((Value::error(format!("invalid reference to {ty}")), 0));
        };
        let Some(ri) = inst.def.resource_index(mode, ty, name) else {
            let what = if mode == Mode::Data {
                format!("data.{ty}.{name}")
            } else {
                format!("{ty}.{name}")
            };
            return Ok((
                Value::error(format!("reference to undeclared resource {what}")),
                1,
            ));
        };
        let mut i = 1;
        let mut key: Option<InstanceKey> = None;
        let mut certainty = Truth::True;
        let mut splat = false;
        let selected = match ops.get(1) {
            Some(TraversalOperator::Index(ix)) => Some(ev.eval(&ix.index, sc)),
            _ => None,
        };
        if let Some(index) = &selected {
            self.mark_sensitive(index);
        }
        let attempt = (|| {
            let indexed = |value: Value| match &selected {
                Some(index) => value.inherit_sensitive(index),
                None => value,
            };
            match ops.get(1) {
                Some(TraversalOperator::Index(_)) => {
                    let index = selected.as_ref().unwrap();
                    key = instance_key(
                        index,
                        inst.def.resources[ri]
                            .block
                            .body
                            .find_attribute("count")
                            .is_some(),
                    );
                    if key.is_none() {
                        if matches!(index.kind, Kind::Known(_)) {
                            return Ok((
                                indexed(Value::error("invalid resource instance index")),
                                2,
                            ));
                        }
                        certainty = tf_eval::truth::uncertainty(index);
                    }
                    i = 2;
                }
                Some(TraversalOperator::LegacyIndex(l)) => {
                    key = Some(InstanceKey::Index(l.index));
                    i = 2;
                }
                Some(TraversalOperator::FullSplat(_) | TraversalOperator::AttrSplat(_)) => {
                    splat = true;
                    i = 2;
                }
                _ => {}
            }
            let base = Address::new(inst.address.clone(), mode, ty, name, None);
            let insts = self.res_instances(inst_id, ri)?;
            if insts.3 {
                return Ok((
                    indexed(Value::unknown(Origin::Limit(
                        "root instance budget exceeded".into(),
                    ))),
                    ops.len(),
                ));
            }
            if splat {
                if insts.0.iter().any(|b| b.key.is_none())
                    && (insts.1.is_some() || insts.2.is_some())
                {
                    return Ok((Value::other("resource instances not expanded"), ops.len()));
                }
                let attr = ops.get(i).and_then(|op| op.attr_name());
                let values = storage::values(
                    insts.0.iter().map(|b| {
                        let mut value = if let Some(attr) = attr {
                            self.resource_attr(inst_id, ri, b.key.clone(), attr, &base)
                        } else {
                            self.resource_object(inst_id, ri, b.key.clone(), &base)
                        };
                        value = reference_value(
                            value,
                            &[tf_eval::prov::ResourceDependency {
                                resource: base.base_string().into(),
                                key: b.key.as_ref().map(InstanceKey::as_str),
                                certainty: b.existence,
                            }],
                            self.budget.storage(),
                        );
                        value
                    }),
                    self.budget.storage(),
                )?;
                let rest = &ops[i + usize::from(attr.is_some())..];
                let mut values = values;
                let result = if matches!(ops.get(1), Some(TraversalOperator::FullSplat(_))) {
                    for value in &mut values {
                        *value = ev.apply_ops(value.clone(), rest, sc);
                    }
                    Value::list(values)
                } else {
                    let n = rest
                        .iter()
                        .take_while(|op| {
                            matches!(
                                op,
                                TraversalOperator::GetAttr(_) | TraversalOperator::LegacyIndex(_)
                            )
                        })
                        .count();
                    for value in &mut values {
                        *value = ev.apply_ops(value.clone(), &rest[..n], sc);
                    }
                    ev.apply_ops(Value::list(values), &rest[n..], sc)
                };
                return Ok((result, ops.len()));
            }
            if i == 2 && key.is_some() && !insts.0.iter().any(|b| b.key == key || b.key.is_none()) {
                return Ok((
                    indexed(Value::error("resource instance index is out of range")),
                    i,
                ));
            }
            let whole = ops.get(i).and_then(|o| o.attr_name()).is_none();
            let dependencies = if splat || (whole && key.is_none() && certainty == Truth::True) {
                insts
                    .0
                    .iter()
                    .map(|b| tf_eval::prov::ResourceDependency {
                        resource: base.base_string().into(),
                        key: b.key.as_ref().map(InstanceKey::as_str),
                        certainty: b.existence,
                    })
                    .collect()
            } else {
                vec![tf_eval::prov::ResourceDependency {
                    resource: base.base_string().into(),
                    key: key.as_ref().map(InstanceKey::as_str),
                    certainty,
                }]
            };
            let referenced = |value: Value| {
                indexed(reference_value(value, &dependencies, self.budget.storage()))
            };
            let Some(attr) = ops.get(i).and_then(|o| o.attr_name()) else {
                let object = |key| self.resource_object(inst_id, ri, key, &base);
                if i == 1 && insts.0.iter().all(|b| b.key.is_some()) {
                    let value = if insts.1.is_some() {
                        Value::list(storage::values(
                            insts.0.iter().map(|b| object(b.key.clone())),
                            self.budget.storage(),
                        )?)
                    } else {
                        storage::object(
                            insts
                                .0
                                .iter()
                                .map(|b| (b.key.as_ref().unwrap().as_str(), object(b.key.clone()))),
                            self.budget.storage(),
                        )?
                    };
                    return Ok((value, i));
                }
                if insts.0.iter().any(|b| b.key == key)
                    && (key.is_some() || (insts.1.is_none() && insts.2.is_none()))
                {
                    return Ok((referenced(object(key)), i));
                }
                let instance = base.with_key(key);
                return Ok((
                    referenced(Value::unknown(instance.computed("(whole object)"))),
                    i,
                ));
            };
            if i == 1 && (insts.1.is_some() || insts.2.is_some()) {
                return Ok((Value::error("resource instance key is required"), i + 1));
            }
            let v = if key.is_none() && i == 2 && !insts.0.is_empty() {
                let choices = storage::values(
                    insts
                        .0
                        .iter()
                        .map(|b| self.resource_attr(inst_id, ri, b.key.clone(), attr, &base)),
                    self.budget.storage(),
                )?;
                storage::alternatives(choices, certainty == Truth::Tainted, self.budget.storage())?
            } else {
                self.resource_attr(inst_id, ri, key, attr, &base)
            };
            Ok((referenced(v), i + 1))
        })();
        attempt.map_err(|stopped| failure(stopped, selected.iter()))
    }

    pub(super) fn resource_object(
        &self,
        inst_id: usize,
        ri: usize,
        key: Option<InstanceKey>,
        base: &Address,
    ) -> Value {
        let inst = self.inst(inst_id);
        let decl = &inst.def.resources[ri];
        let dependency = tf_eval::prov::ResourceDependency {
            resource: base.base_string().into(),
            key: key.as_ref().map(InstanceKey::as_str),
            certainty: Truth::True,
        };
        let attempt = (|| -> Build<Value> {
            let mut names = Buffer::new(self.budget.storage());
            for name in decl
                .block
                .body
                .attributes()
                .map(|a| a.key.name.as_str())
                .filter(|n| !META_ATTRS.contains(n))
            {
                names.push(name)?;
            }
            for block in decl.block.body.blocks() {
                let name = block.block_type();
                if name == "dynamic" {
                    if let Some(label) = block.labels.first() {
                        names.push(label.value.as_str())?;
                    }
                } else if !META_BLOCKS.contains(&name) {
                    names.push(name)?;
                }
            }
            if let Some(schema) = decl.schema {
                for attr in &schema.attributes {
                    names.push(attr.name)?;
                }
                for block in &schema.block_types {
                    names.push(block.name)?;
                }
            }
            let mut names = names.finish();
            names.sort_unstable();
            names.dedup();
            let value = storage::object(
                names.into_iter().map(|name| {
                    (
                        Arc::from(name),
                        self.resource_attr(inst_id, ri, key.clone(), name, base),
                    )
                }),
                self.budget.storage(),
            )?;
            Ok(reference_value(value, &[dependency], self.budget.storage()))
        })();
        attempt.unwrap_or_else(|stopped| stopped)
    }

    #[expect(clippy::too_many_lines)]
    pub(super) fn resource_attr(
        &self,
        inst_id: usize,
        ri: usize,
        key: Option<InstanceKey>,
        attr: &str,
        base: &Address,
    ) -> Value {
        let inst = self.inst(inst_id);
        let k = (ri, key.clone(), attr.to_string());
        let instance = base.clone().with_key(key.clone());
        let base_str = base.base_string();
        self.memo(
            &inst.res_attrs,
            &k,
            || k.clone(),
            || format!("{base}.{attr}"),
            || {
                let decl: &ResourceDecl<'a> = &inst.def.resources[ri];
                if decl.mode == Mode::Data
                    && decl.ty == "aws_iam_policy_document"
                    && (attr == "json" || attr == "minified_json")
                {
                    return self.iam_policy_document(inst_id, ri, key.as_ref(), &base_str);
                }
                if let Some(a) = decl
                    .block
                    .body
                    .find_attribute(attr)
                    .filter(|_| !META_ATTRS.contains(&attr))
                {
                    let insts = match self.res_instances(inst_id, ri) {
                        Ok(insts) => insts,
                        Err(stopped) => return stopped,
                    };
                    let chosen = match &key {
                        Some(k) => insts.0.iter().find(|b| b.key.as_ref() == Some(k)),
                        None => None,
                    }
                    .or(if insts.0.len() == 1 {
                        insts.0.first()
                    } else {
                        None
                    });
                    let fallback;
                    let binds = match chosen {
                        Some(binding) => binding.binds.as_slice(),
                        None => {
                            let count = match self
                                .obj1("index", Value::other("count.index (instance not selected)"))
                            {
                                Ok(value) => value,
                                Err(stopped) => return stopped,
                            };
                            fallback = [
                                ("count", count),
                                ("each", Value::other("each (instance not selected)")),
                            ];
                            &fallback
                        }
                    };
                    let file = inst.def.origins.file(a, decl.file);
                    let mut v =
                        Scope::EMPTY.with_all(binds, |sc| self.eval(inst_id, file, &a.value, sc));
                    if decl
                        .schema
                        .and_then(|s| s.attribute(attr))
                        .is_some_and(|a| a.is_sensitive())
                    {
                        v = v.sensitive();
                        self.files.mark_sensitive(FileSpan::new(file, a.span));
                        self.mark_sensitive(&v);
                    }
                    // A null in configuration leaves a computed attribute to
                    // the provider.
                    let is_computed = decl
                        .schema
                        .and_then(|s| s.attribute(attr))
                        .is_some_and(|at| at.is_computed());
                    if v.is_null() && is_computed {
                        return Value::unknown(instance.computed(attr));
                    }
                    return v.push(
                        Step::new(
                            StepKind::Attribute,
                            FileSpan::new(file, a.span),
                            format!("{base_str} {attr}"),
                        )
                        .with_resource(base_str.clone().into())
                        .with_attribute(attr),
                    );
                }
                let computed = || Value::unknown(instance.computed(attr));
                match decl.schema {
                    Some(s) => match s.member(attr) {
                        Some(Member::Attribute(at)) if at.is_computed() => computed(),
                        Some(Member::Attribute(_)) => tf_schema::default_for(decl.ty, attr)
                            .map(model::default_value)
                            .unwrap_or_else(Value::null),
                        Some(Member::Block(_)) => {
                            Value::other(format!("nested block reference {base_str}.{attr}"))
                        }
                        None => {
                            Value::error(format!("unsupported attribute \"{attr}\" on {}", decl.ty))
                        }
                    },
                    None => computed(),
                }
            },
        )
    }

    #[expect(clippy::too_many_lines)]
    pub(super) fn module_ref(
        &self,
        inst_id: usize,
        ops: &'a [TraversalOperator<'a>],
        ev: &Evaluator<'_, 'a>,
        sc: Scope<'_>,
    ) -> Build<(Value, usize)> {
        let inst = self.inst(inst_id);
        let Some(name) = ops.first().and_then(|o| o.attr_name()) else {
            return Ok((Value::error("invalid module reference"), 0));
        };
        let Some(ci) = inst.def.module_call(name) else {
            return Ok((
                Value::error(format!("reference to undeclared module \"{name}\"")),
                1,
            ));
        };
        let call = &inst.def.module_calls[ci];
        let maddr = format!("{}module.{name}", inst.prefix());
        let selected = match ops.get(1) {
            Some(TraversalOperator::Index(ix)) => Some(ev.eval(&ix.index, sc)),
            Some(TraversalOperator::LegacyIndex(ix)) => Some(Value::number(ix.index as f64)),
            _ => None,
        };
        if let Some(index) = &selected {
            self.mark_sensitive(index);
        }
        let attempt = (|| {
            let indexed = |value: Value| match &selected {
                Some(index) => value.inherit_sensitive(index),
                None => value,
            };
            if matches!(call.source, ModuleSource::Invalid) {
                return Ok((
                    indexed(Value::other(format!(
                        "{maddr}: module source not a literal"
                    ))),
                    1,
                ));
            }
            let kids = self.children_of(inst_id, ci)?;
            if inst.limited_children.borrow().contains(&ci) {
                return Ok((
                    indexed(Value::unknown(Origin::Limit(
                        "root instance budget exceeded".into(),
                    ))),
                    ops.len(),
                ));
            }
            let counted = call.block.body.find_attribute("count").is_some();
            let repeated = counted || call.block.body.find_attribute("for_each").is_some();
            // No selected instance is not the same as an unavailable package.
            if kids.is_empty() && matches!(call.source, ModuleSource::Remote(_)) {
                let (binds, _, _) =
                    self.expand_inner(inst_id, call.file, &call.block.body, Scope::EMPTY)?;
                if !binds.is_empty() {
                    return Ok((
                        indexed(Value::unknown(Origin::RemoteModule {
                            module: maddr.into(),
                            output: "(unavailable module)".into(),
                        })),
                        ops.len(),
                    ));
                }
            }
            let object = |kid: usize| {
                let child = self.inst(kid);
                storage::object(
                    child
                        .def
                        .outputs
                        .iter()
                        .map(|o| (Arc::from(o.name), self.output_value(kid, o.name))),
                    self.budget.storage(),
                )
                .unwrap_or_else(|stopped| stopped)
            };
            if let Some(index) = &selected {
                let key = instance_key(index, counted);
                let kid = key
                    .as_ref()
                    .and_then(|key| kids.iter().find(|(k, _)| k.as_ref() == Some(key)))
                    .or_else(|| kids.iter().find(|(k, _)| k.is_none() && repeated));
                if let Some((_, kid)) = kid {
                    if let Some(out) = ops.get(2).and_then(|op| op.attr_name()) {
                        return Ok((indexed(self.output_value(*kid, out)), 3));
                    }
                    return Ok((indexed(object(*kid)), 2));
                }
                if matches!(index.kind, Kind::Known(_)) {
                    return Ok((
                        indexed(Value::error(
                            "module instance index is out of range or invalid",
                        )),
                        2,
                    ));
                }
                let choices =
                    storage::values(kids.iter().map(|(_, k)| object(*k)), self.budget.storage())?;
                let value = storage::alternatives(
                    choices,
                    tf_eval::truth::uncertainty(index) == Truth::Tainted,
                    self.budget.storage(),
                )?;
                return Ok((indexed(value), 2));
            }
            if !repeated {
                if let Some((_, kid)) = kids.first() {
                    if let Some(out) = ops.get(1).and_then(|op| op.attr_name()) {
                        return Ok((self.output_value(*kid, out), 2));
                    }
                    return Ok((object(*kid), 1));
                }
                return Ok((Value::other(format!("{maddr}: module not instantiated")), 1));
            }
            if kids.iter().any(|(k, _)| k.is_none()) {
                return Ok((
                    Value::other(format!("{maddr}: module instances not expanded")),
                    ops.len(),
                ));
            }
            let value = if counted {
                Value::list(storage::values(
                    kids.iter().map(|(_, k)| object(*k)),
                    self.budget.storage(),
                )?)
            } else {
                storage::object(
                    kids.iter()
                        .map(|(key, k)| (key.as_ref().unwrap().as_str(), object(*k))),
                    self.budget.storage(),
                )?
            };
            Ok((value, 1))
        })();
        attempt.map_err(|stopped| failure(stopped, selected.iter()))
    }
}
