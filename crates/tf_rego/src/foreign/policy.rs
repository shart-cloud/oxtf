use super::*;

/// `OXTF_POLICY_TRACE=FILE` appends one JSON line per evaluation (entry,
/// input, raw result) for the `opa eval` conformance harness.
#[derive(Clone)]
pub(super) struct Trace(Arc<Mutex<std::fs::File>>);

impl Trace {
    pub(super) fn from_env() -> Result<Option<Trace>, String> {
        let Some(path) = std::env::var_os("OXTF_POLICY_TRACE") else {
            return Ok(None);
        };
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("OXTF_POLICY_TRACE {}: {e}", Path::new(&path).display()))?;
        Ok(Some(Trace(Arc::new(Mutex::new(file)))))
    }

    pub(super) fn record(
        &self,
        entry: &str,
        input: &Json,
        file: Option<(&Path, bool)>,
        result: &Result<regorus::Value, String>,
    ) {
        let mut line = match result {
            Ok(v) => json!({"entry": entry, "input": input, "result": to_serde(v).ok()}),
            Err(e) => json!({"entry": entry, "input": input, "error": e}),
        };
        if let Some((f, whole)) = file {
            line["file"] = json!(f.display().to_string());
            line["whole_file"] = json!(whole);
        }
        let mut f = self.0.lock().expect("trace lock");
        let _ = writeln!(f, "{line}");
    }
}

pub(super) struct ForeignPolicy {
    pub(super) info: RuleInfo,
    pub(super) types: Option<Vec<String>>,
    pub(super) input: Input,
    pub(super) bundle: Arc<Bundle>,
    pub(super) entry: String,
    pub(super) shape: Shape,
    pub(super) exception: Option<Exception>,
    pub(super) trace: Option<Trace>,
}

pub(super) struct PolicyRun<'a> {
    pub(super) policy: &'a ForeignPolicy,
    pub(super) budget: &'a tf_linter::RuleBudget,
}

impl std::ops::Deref for PolicyRun<'_> {
    type Target = ForeignPolicy;
    fn deref(&self) -> &Self::Target {
        self.policy
    }
}

impl PolicyRun<'_> {
    pub(super) fn run(&self, input: Json) -> Result<Vec<Violation>, String> {
        self.run_on(regorus::Value::from(input), None, true)
    }

    /// [`PolicyRun::run`] with Conftest's `data.conftest.file` set to
    /// the file under evaluation.
    /// A file document (`whole`) or one instance alone (ablation, which
    /// asks only whether the instance produces the violation: exceptions
    /// were already decided on the whole file).
    pub(super) fn run_file(
        &self,
        input: regorus::Value,
        file: &Path,
        whole: bool,
    ) -> Result<Vec<Violation>, String> {
        self.run_on(input, Some((file, whole)), whole)
    }

    /// Evaluate `rule` on a reused working copy of the bundle's engine. For
    /// a file and a rule that may read it, `data.conftest.file` is set with
    /// Rego's `with`, which needs no re-prepared engine.
    pub(super) fn evaluate(
        &self,
        file: Option<&Path>,
        input: regorus::Value,
        rule: &str,
    ) -> Result<regorus::Value, String> {
        let with = self.file_info(file, rule);
        self.budget.charge(1)?;
        let remaining = self.budget.rego_remaining()?;
        let started = std::time::Instant::now();
        let mut engine = self
            .budget
            .with_cache(|cache: &mut BackendCache| cache.engines.remove(&self.bundle.id))
            .unwrap_or_else(|| self.bundle.engine.clone());
        engine.set_execution_timer_config(timer_config(remaining));
        engine.set_input(input);
        let failure = |error: anyhow::Error| {
            if matches!(
                error.downcast_ref::<regorus::utils::limits::LimitError>(),
                Some(regorus::utils::limits::LimitError::TimeLimitExceeded { .. })
            ) {
                self.budget.exhaust_rego_time()
            } else {
                error.to_string()
            }
        };
        let result = match &with {
            None => engine.eval_rule(rule.to_string()).map_err(failure),
            Some(info) => engine
                .eval_query(
                    format!("__oxtf_result := {rule} with data.conftest.file as {info}"),
                    false,
                )
                .map_err(failure)
                .map(|r| {
                    r.result
                        .first()
                        .and_then(|r| {
                            r.bindings.as_object().ok().and_then(|b| {
                                b.get(&regorus::Value::from("__oxtf_result")).cloned()
                            })
                        })
                        .unwrap_or(regorus::Value::Undefined)
                }),
        };
        self.budget.with_cache(|cache: &mut BackendCache| {
            cache.engines.insert(self.bundle.id, engine);
        });
        self.budget.record_rego_elapsed(started.elapsed())?;
        result
    }

    pub(super) fn file_info(&self, file: Option<&Path>, rule: &str) -> Option<Json> {
        let reads = rule
            .strip_prefix("data.")
            .map(|r| r.split('.').map(str::to_string).collect::<Vec<_>>())
            .is_some_and(|p| self.bundle.file_info.contains(&p));
        match file {
            Some(f) if reads => {
                let abs = std::path::absolute(f).unwrap_or_else(|_| f.to_path_buf());
                Some(json!({
                    "name": abs.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
                    "dir": abs.parent().map(|d| d.display().to_string()).unwrap_or_default(),
                }))
            }
            _ => None,
        }
    }

    pub(super) fn cache<R>(&self, f: impl FnOnce(&mut RootCache) -> R) -> R {
        self.budget.with_cache(|cache: &mut BackendCache| {
            f(cache.roots.entry(self.bundle.id).or_default())
        })
    }

    /// The file's rendered document, shared by the bundle's rules for this
    /// root.
    pub(super) fn document(&self, cf: &ConfigFile<'_>) -> Result<Arc<CachedDocument>, String> {
        crate::budget::text(self.budget, &cf.source.text)?;
        for resource in &cf.module.resources {
            if resource.span.file == cf.source.id {
                crate::budget::body(self.budget, &resource.body)?;
            }
        }
        let key = (std::ptr::from_ref(cf.module) as usize, cf.source.id);
        if let Some(d) = self.cache(|cache| cache.documents.get(&key).cloned()) {
            return Ok(d);
        }
        let fd = crate::hcl2json::evaluated(cf)?;
        let instances = fd
            .instances
            .into_iter()
            .map(|i| {
                let index = cf
                    .module
                    .resources
                    .iter()
                    .position(|r| std::ptr::eq(r, i.resource))
                    .expect("an instance of this module");
                (index, regorus::Value::from(i.doc))
            })
            .collect();
        let d = Arc::new(CachedDocument {
            doc: regorus::Value::from(fd.doc),
            abstractions: fd.abstractions,
            instances,
        });
        self.cache(|cache| cache.documents.insert(key, d.clone()));
        Ok(d)
    }

    /// `file`: the document's file, and whether this is the whole file (not
    /// one instance alone, for ablation); for the trace only.
    pub(super) fn run_on(
        &self,
        input: regorus::Value,
        file: Option<(&Path, bool)>,
        exceptions: bool,
    ) -> Result<Vec<Violation>, String> {
        let path = file.map(|(f, _)| f);
        if exceptions
            && let Some(e) = &self.exception
            && self.is_excepted(&input, path, e)?
        {
            return Ok(Vec::new());
        }
        let result = self.evaluate(path, input.clone(), &self.entry);
        if let Ok(value) = &result {
            crate::budget::result(self.budget, value)?;
        }
        if let Some(t) = &self.trace {
            t.record(
                &self.entry,
                &to_serde(&input).unwrap_or(Json::Null),
                file,
                &result,
            );
        }
        violations(&result?)
    }

    /// The exception check, with the set's value cached per (exception
    /// rule, file) for a root.
    pub(super) fn is_excepted(
        &self,
        input: &regorus::Value,
        file: Option<&Path>,
        e: &Exception,
    ) -> Result<bool, String> {
        let Some(file) = file else {
            let value = self.evaluate(None, input.clone(), &e.rule)?;
            crate::budget::result(self.budget, &value)?;
            return exception_names(&value, e);
        };
        // The set depends on the file, not on the rule asking: evaluate it
        // once per file and test each rule's name against it.
        let key = (e.rule.clone(), file.to_path_buf());
        let cached = self.cache(|cache| cache.exceptions.get(&key).cloned());
        let value = match cached {
            Some(v) => v,
            None => {
                let v = self.evaluate(Some(file), input.clone(), &e.rule)?;
                self.cache(|cache| cache.exceptions.insert(key, v.clone()));
                v
            }
        };
        crate::budget::result(self.budget, &value)?;
        exception_names(&value, e)
    }

    pub(super) fn judgement(
        &self,
        r: &Resource,
        v: &Violation,
        abstractions: &[Abstraction],
    ) -> Judgement {
        let mut j = self.judgement_on(Some(r), v, abstractions);
        if j.witness.is_none() && j.certainty == Certainty::Definite {
            j.witness = v.path.as_deref().and_then(|path| locate(&r.body, path));
        }
        j
    }

    pub(super) fn judgement_on(
        &self,
        r: Option<&Resource>,
        v: &Violation,
        abstractions: &[Abstraction],
    ) -> Judgement {
        let p = Projection {
            attributes: JsonMap::new(),
            abstractions: abstractions.to_vec(),
        };
        let certainty = p.certainty();
        let witness = match (certainty, p.deciding()) {
            (Certainty::Definite, _) | (_, None) => {
                r.and_then(|r| v.path.as_deref().and_then(|path| locate(&r.body, path)))
            }
            (_, Some(a)) => Some(a.value.clone()),
        };
        let suffix = match certainty {
            Certainty::Indeterminate => {
                let paths: Vec<_> = abstractions.iter().map(|a| a.path.as_str()).collect();
                format!(
                    " (cannot be confirmed: {} computed at apply time)",
                    paths.join(", ")
                )
            }
            _ => String::new(),
        };
        Judgement {
            certainty,
            witness,
            message: format!("{}{suffix}", v.msg),
            hidden: abstractions
                .iter()
                .map(|a| Hidden {
                    path: a.path.clone(),
                    truth: a.truth,
                })
                .collect(),
            fix_hint: r.zip(v.fix.as_ref()).map(|(r, (attribute, value))| {
                tf_linter::FixHint::set(r, attribute, value.clone())
            }),
        }
    }

    pub(super) fn judge(&self, r: &Resource) -> Result<Vec<Judgement>, String> {
        crate::budget::body(self.budget, &r.body)?;
        let projection = projection::project(r);
        let input = projection::input(r, &projection, self.shape);
        let found = self.run(input)?;
        found
            .iter()
            .map(|v| match &v.address {
                Some(a) if **a != *r.address => Err(format!(
                    "violation names {a}, but the input held only {}",
                    r.address
                )),
                _ => Ok(self.judgement(r, v, &projection.abstractions)),
            })
            .collect()
    }

    /// Every managed instance of the root (of the declared types) in one
    /// plan document, and each instance alone.
    pub(super) fn plan_document<'a>(
        &self,
        resources: &[&'a Resource],
    ) -> Result<PlanDocument<'a>, String> {
        self.budget.charge(resources.len() as u64)?;
        let selected = resources
            .iter()
            .copied()
            .filter(|r| r.mode == tf_semantic::Mode::Managed && r.existence != Truth::False)
            .filter(|r| {
                self.types
                    .as_ref()
                    .is_none_or(|t| t.iter().any(|t| *t == *r.ty))
            });
        let mut changes = Vec::new();
        let mut planned = Vec::new();
        let mut abstractions = Vec::new();
        let mut instances = Vec::new();
        for r in selected {
            crate::budget::body(self.budget, &r.body)?;
            let p = projection::project(r);
            let doc = projection::input(r, &p, Shape::Plan);
            changes.extend(
                doc["resource_changes"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default(),
            );
            planned.extend(
                doc["planned_values"]["root_module"]["resources"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default(),
            );
            abstractions.extend(p.abstractions.into_iter().map(|mut a| {
                a.path = format!("{}.{}", r.address, a.path);
                a
            }));
            if r.existence != Truth::True {
                abstractions.push(Abstraction {
                    path: r.address.to_string(),
                    truth: if r.existence == Truth::Tainted {
                        Truth::Tainted
                    } else {
                        Truth::Unknown
                    },
                    value: Value::other("resource existence"),
                });
            }
            instances.push((r, doc));
        }
        Ok(PlanDocument {
            doc: json!({
                "format_version": "1.2",
                "resource_changes": changes,
                "planned_values": {"root_module": {"resources": planned}},
            }),
            abstractions,
            instances,
        })
    }

    /// Module input: results attributed by `address`.
    pub(super) fn judge_root<'a>(
        &self,
        resources: &[&'a Resource],
    ) -> Result<Vec<(&'a Resource, Judgement)>, String> {
        let pd = self.plan_document(resources)?;
        let found = self.run(pd.doc)?;
        found
            .iter()
            .map(|v| {
                let a = v.address.as_deref().ok_or_else(|| {
                    format!("module-input violation without an address: {}", v.msg)
                })?;
                let r = pd
                    .instances
                    .iter()
                    .find(|(r, _)| *r.address == *a)
                    .map(|(r, _)| *r)
                    .ok_or_else(|| format!("violation names {a}, which is not in the input"))?;
                Ok((r, self.judgement(r, v, &pd.abstractions)))
            })
            .collect()
    }

    /// Ablation: the owners of each violation of a whole document are the
    /// instances that reproduce it alone (the one its `address` names, when
    /// it names one).
    pub(super) fn attribute<'a, D: Clone>(
        &self,
        found: Vec<Violation>,
        instances: &[(&'a Resource, D)],
        run: impl Fn(D) -> Result<Vec<Violation>, String>,
    ) -> Result<Vec<(Violation, Vec<&'a Resource>)>, String> {
        if found.is_empty() {
            return Ok(Vec::new());
        }
        self.budget.charge(instances.len() as u64)?;
        self.budget.charge(found.len() as u64)?;
        // The ablation runs are only needed for violations that name no
        // instance.
        let mut alone: Vec<Vec<String>> = Vec::new();
        if found.iter().any(|v| v.address.is_none()) {
            for (_, doc) in instances {
                alone.push(run(doc.clone())?.into_iter().map(|v| v.msg).collect());
            }
        }
        found
            .into_iter()
            .map(|v| {
                self.budget.charge(instances.len() as u64)?;
                let owners: Vec<&'a Resource> = match &v.address {
                    Some(a) => vec![
                        instances
                            .iter()
                            .find(|(r, _)| *r.address == **a)
                            .map(|(r, _)| *r)
                            .ok_or_else(|| {
                                format!("violation names {a}, which is not in the input")
                            })?,
                    ],
                    None => instances
                        .iter()
                        .zip(&alone)
                        .filter(|(_, msgs)| msgs.contains(&v.msg))
                        .map(|((r, _), _)| *r)
                        .collect(),
                };
                Ok((v, owners))
            })
            .collect()
    }

    /// Document input: per file (HCL shape) or per root (plan shape).
    pub(super) fn judge_documents<'a>(
        &self,
        analysis: &'a tf_semantic::Analysis,
        files: &[ConfigFile<'a>],
    ) -> Result<Vec<(Subject<'a>, Judgement)>, String> {
        match self.shape {
            Shape::Hcl => self.judge_hcl(analysis, files),
            Shape::Plan => self.judge_plan(analysis),
        }
    }

    pub(super) fn judge_hcl<'a>(
        &self,
        analysis: &'a tf_semantic::Analysis,
        files: &[ConfigFile<'a>],
    ) -> Result<Vec<(Subject<'a>, Judgement)>, String> {
        self.budget.charge(files.len() as u64)?;
        let mut out = Vec::new();
        if files.is_empty() && analysis.modules.iter().any(|m| !m.resources.is_empty()) {
            return Err(
                "the HCL input shape needs source files; scan a plan with the plan shape".into(),
            );
        }
        for cf in files {
            let path = &cf.source.path;
            let at = |e: String| format!("{}: {e}", path.display());
            let fd = self.document(cf).map_err(at)?;
            let found = self.run_file(fd.doc.clone(), path, true).map_err(at)?;
            let instances: Vec<(&'a Resource, regorus::Value)> = fd
                .instances
                .iter()
                .map(|(i, doc)| (&cf.module.resources[*i], doc.clone()))
                .collect();
            for (v, owners) in self
                .attribute(found, &instances, |d| self.run_file(d, path, false))
                .map_err(at)?
            {
                if owners.is_empty() {
                    out.push((
                        Subject::File {
                            module: cf.module,
                            file: cf.source.id,
                        },
                        self.judgement_on(None, &v, &fd.abstractions),
                    ));
                }
                for r in owners {
                    out.push((
                        Subject::Resource(r),
                        self.judgement(r, &v, &fd.abstractions),
                    ));
                }
            }
        }
        Ok(out)
    }

    pub(super) fn judge_plan<'a>(
        &self,
        analysis: &'a tf_semantic::Analysis,
    ) -> Result<Vec<(Subject<'a>, Judgement)>, String> {
        for module in &analysis.modules {
            self.budget.charge(module.resources.len() as u64)?;
        }
        let mut out = Vec::new();
        let resources: Vec<&'a Resource> =
            analysis.modules.iter().flat_map(|m| &m.resources).collect();
        let pd = self.plan_document(&resources)?;
        let found = self.run(pd.doc)?;
        let mut lost = Vec::new();
        for (v, owners) in self.attribute(found, &pd.instances, |d| self.run(d))? {
            if owners.is_empty() {
                lost.push(v.msg.clone());
            }
            for r in owners {
                out.push((
                    Subject::Resource(r),
                    self.judgement(r, &v, &pd.abstractions),
                ));
            }
        }
        if !lost.is_empty() {
            return Err(format!(
                "no single resource reproduces these plan violations (a plan has no file to report them on): {}",
                lost.join("; ")
            ));
        }
        Ok(out)
    }
}

pub(super) struct PlanDocument<'a> {
    pub(super) doc: Json,
    pub(super) abstractions: Vec<Abstraction>,
    pub(super) instances: Vec<(&'a Resource, Json)>,
}

impl DynRule for ForeignPolicy {
    fn info(&self) -> RuleInfo {
        self.info.clone()
    }
    fn needs_graph(&self) -> bool {
        self.input == Input::Module
    }
    fn needs_files(&self) -> bool {
        self.input == Input::Document
    }
    fn judge_files<'a>(
        &self,
        analysis: &'a tf_semantic::Analysis,
        files: &[ConfigFile<'a>],
    ) -> Result<Vec<(Subject<'a>, Judgement)>, RuleFailure> {
        self.judge_files_with_budget(analysis, files, &tf_linter::RuleBudget::default())
    }
    fn judge_graph<'a>(
        &self,
        graph: &tf_semantic::graph::ResourceGraph<'a>,
    ) -> Result<Vec<(&'a Resource, Judgement)>, RuleFailure> {
        self.judge_graph_with_budget(graph, &tf_linter::RuleBudget::default())
    }
    fn judge_resource(&self, r: &Resource) -> Result<Vec<Judgement>, RuleFailure> {
        self.judge_resource_with_budget(r, &tf_linter::RuleBudget::default())
    }
    fn judge_files_with_budget<'a>(
        &self,
        analysis: &'a tf_semantic::Analysis,
        files: &[ConfigFile<'a>],
        budget: &tf_linter::RuleBudget,
    ) -> Result<Vec<(Subject<'a>, Judgement)>, RuleFailure> {
        budget.finish(
            PolicyRun {
                policy: self,
                budget,
            }
            .judge_documents(analysis, files),
        )
    }
    fn judge_graph_with_budget<'a>(
        &self,
        graph: &tf_semantic::graph::ResourceGraph<'a>,
        budget: &tf_linter::RuleBudget,
    ) -> Result<Vec<(&'a Resource, Judgement)>, RuleFailure> {
        budget.finish(
            PolicyRun {
                policy: self,
                budget,
            }
            .judge_root(&graph.resources),
        )
    }
    fn judge_resource_with_budget(
        &self,
        r: &Resource,
        budget: &tf_linter::RuleBudget,
    ) -> Result<Vec<Judgement>, RuleFailure> {
        if self.input != Input::Resource {
            return Ok(Vec::new());
        }
        budget.finish(
            PolicyRun {
                policy: self,
                budget,
            }
            .judge(r),
        )
    }
    fn judge_module<'m>(
        &self,
        _m: &'m tf_semantic::Module,
    ) -> Result<Vec<(&'m Resource, Judgement)>, RuleFailure> {
        Ok(Vec::new())
    }
}
