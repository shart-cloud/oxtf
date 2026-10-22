use super::*;

impl Analyzer<'_, '_> {
    // ---- data sources evaluated statically ------------------------------

    /// `data.aws_iam_policy_document.x.json`: the provider renders the
    /// `statement` blocks (and `source_policy_documents` /
    /// `override_policy_documents`) to JSON deterministically, so it is
    /// evaluated here instead of being left Unknown. `condition` blocks are
    /// not rendered; override documents are appended (not merged by Sid).
    pub(super) fn iam_policy_document(
        &self,
        inst_id: usize,
        ri: usize,
        key: Option<&InstanceKey>,
        base: &str,
    ) -> Value {
        let result = self
            .iam_policy_body(inst_id, ri, key, base)
            .and_then(|body| {
                self.iam_document(&body, base)
                    .map_err(|stopped| body_failure(stopped, &body))
            });
        let inst = self.inst(inst_id);
        let decl = &inst.def.resources[ri];
        result.unwrap_or_else(|stopped| stopped).push(
            Step::new(
                StepKind::Attribute,
                FileSpan::new(decl.file, header_span(decl.block)),
                format!("{base}.json (rendered from statement blocks)"),
            )
            .with_resource(base.into()),
        )
    }

    fn iam_policy_body(
        &self,
        inst_id: usize,
        ri: usize,
        key: Option<&InstanceKey>,
        base: &str,
    ) -> Build<model::Body> {
        let inst = self.inst(inst_id);
        let decl = &inst.def.resources[ri];
        let insts = self.res_instances(inst_id, ri)?;
        let binds = key
            .and_then(|k| insts.0.iter().find(|b| b.key.as_ref() == Some(k)))
            .or(if insts.0.len() == 1 {
                insts.0.first()
            } else {
                None
            })
            .map(|b| b.binds.as_slice())
            .unwrap_or_default();
        let ctx = BodyCtx {
            inst: inst_id,
            file: decl.file,
            origins: &inst.def.origins,
            addr: base.into(),
            base: base.into(),
            ty: decl.ty,
            mode: decl.mode,
            strict_bool: false,
            observe: false,
        };
        Scope::EMPTY.with_all(binds, |sc| {
            self.eval_body(
                &ctx,
                &decl.block.body,
                decl.schema.map(|s| s.block()),
                sc,
                "",
                true,
            )
        })
    }

    fn iam_document(&self, body: &model::Body, base: &str) -> Build<Value> {
        let mut statements = Buffer::new(self.budget.storage());
        for source in ["source_policy_documents", "override_policy_documents"] {
            if let Some(documents) = body.value(source) {
                self.iam_sources(documents, source, base, &mut statements)?;
            }
        }
        for block in body.blocks_of("statement") {
            statements.reserve(1)?;
            let statement = self.iam_statement(&block.body)?;
            let value = match block.existence {
                Truth::True => statement,
                existence => {
                    let choices = collections::collect(
                        [statement, Value::null()].into_iter(),
                        self.budget.storage(),
                    )?;
                    storage::alternatives(
                        choices,
                        existence == Truth::Tainted,
                        self.budget.storage(),
                    )?
                }
            };
            statements.push(value)?;
        }
        let version = body
            .value("version")
            .filter(|v| !v.is_null())
            .cloned()
            .unwrap_or_else(|| Value::string("2012-10-17"));
        let doc = storage::object(
            [
                ("Version".into(), version),
                ("Statement".into(), Value::list(statements.finish())),
            ]
            .into_iter(),
            self.budget.storage(),
        )?;
        tf_eval::functions::encoded(doc, self.budget.storage())
    }

    fn iam_sources(
        &self,
        documents: &Value,
        source: &str,
        base: &str,
        out: &mut Buffer<'_, Value>,
    ) -> Build<()> {
        let Some(items) = documents.as_list() else {
            return if documents.is_null() {
                Ok(())
            } else {
                Err(documents.clone())
            };
        };
        for document in items {
            let document = document.child_of(documents);
            let parsed = match &document.kind {
                Kind::Known(Known::Json(inner)) => (**inner).clone(),
                Kind::Known(Known::String(_)) => {
                    let args = collections::collect(
                        std::iter::once(document.clone()),
                        self.budget.storage(),
                    )?;
                    tf_eval::functions::call_budgeted("jsondecode", args, self.budget.storage())
                }
                _ => {
                    return Err(Value::other(format!("{base}.json: {source} not known"))
                        .with_prov(document.prov.clone()));
                }
            };
            let statement = parsed.get_attr("Statement");
            if let Some(items) = statement.as_list() {
                out.reserve(items.len())?;
                for item in items {
                    out.push(item.child_of(&statement))?;
                }
            } else if statement.is_known() {
                out.push(statement)?;
            } else {
                return Err(statement);
            }
        }
        Ok(())
    }

    fn iam_statement(&self, body: &model::Body) -> Build<Value> {
        let mut map = Map::new();
        for (source, target) in [
            ("sid", "Sid"),
            ("effect", "Effect"),
            ("actions", "Action"),
            ("not_actions", "NotAction"),
            ("resources", "Resource"),
            ("not_resources", "NotResource"),
        ] {
            if let Some(value) = body.value(source).filter(|v| !v.is_null()) {
                collections::insert(
                    &mut map,
                    target.into(),
                    value.clone(),
                    self.budget.storage(),
                )?;
            }
        }
        if !map.contains_key("Effect") {
            collections::insert(
                &mut map,
                "Effect".into(),
                Value::string("Allow"),
                self.budget.storage(),
            )?;
        }
        for (block, key) in [
            ("principals", "Principal"),
            ("not_principals", "NotPrincipal"),
        ] {
            let mut principals = Map::new();
            for principal in body.blocks_of(block) {
                if let (Some(ty), Some(ids)) = (
                    principal.body.value("type").and_then(|v| v.to_str()),
                    principal.body.value("identifiers"),
                ) {
                    collections::insert(&mut principals, ty, ids.clone(), self.budget.storage())?;
                }
            }
            if !principals.is_empty() {
                collections::insert(
                    &mut map,
                    key.into(),
                    Value::object(principals),
                    self.budget.storage(),
                )?;
            }
        }
        Ok(Value::object(map))
    }
}
