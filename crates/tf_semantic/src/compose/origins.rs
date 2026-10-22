use super::*;
use rustc_hash::FxHashMap;
use tf_limits::input::InputBudget;

/// Source ownership for composed nodes. Empty for modules without overrides.
/// Keys are addresses of immutable arena nodes; no pointer is dereferenced.
#[derive(Default)]
pub struct Origins {
    locations: FxHashMap<usize, FileId>,
    pub(super) defaults: FxHashMap<usize, DefaultValue>,
    type_defaults: FxHashMap<usize, TypeDefaults>,
}

impl Origins {
    pub(super) fn prepare_block(
        &mut self,
        b: &Block<'_>,
        sf: &SourceFile,
        budget: &tf_eval::EvaluationBudget,
        errors: &mut Vec<(FileSpan, String)>,
    ) -> AllocResult<()> {
        let cx = DefaultContext {
            budget,
            at: FileSpan::new(sf.id, b.span),
        };
        self.insert(b, sf.id, budget.storage())?;
        self.body(&b.body, sf.id, budget.storage())?;
        if b.block_type() == "variable"
            && let Some(ty) = b.body.find_attribute("type")
            && !crate::variable_defaults::valid_type(&ty.value)
        {
            errors.push((
                FileSpan::new(sf.id, ty.span),
                "invalid variable type constraint".into(),
            ));
        }
        if b.block_type() == "variable" {
            if !is_override(&sf.path) {
                self.prepare_type_defaults(b, sf, cx, errors)?;
            }
            self.prepare_default(b, sf, cx, errors)?;
        }
        Ok(())
    }

    fn prepare_type_defaults(
        &mut self,
        b: &Block<'_>,
        sf: &SourceFile,
        cx: DefaultContext<'_>,
        errors: &mut Vec<(FileSpan, String)>,
    ) -> AllocResult<()> {
        let key = std::ptr::from_ref(b) as usize;
        storage::map_slot(&mut self.type_defaults, &key, cx.budget.storage())?;
        let defaults = match b.body.find_attribute("type") {
            Some(ty) => TypeDefaults::from_type(&ty.value, cx).unwrap_or_else(|error| {
                if error == DefaultError::Invalid {
                    errors.push((
                        FileSpan::new(sf.id, ty.span),
                        "invalid optional attribute default".into(),
                    ));
                }
                TypeDefaults::default()
            }),
            None => TypeDefaults::default(),
        };
        self.type_defaults.insert(key, defaults);
        cx.budget.storage().admit_collection(0)
    }

    pub fn file<T>(&self, node: &T, fallback: FileId) -> FileId {
        self.locations
            .get(&(std::ptr::from_ref(node) as usize))
            .copied()
            .unwrap_or(fallback)
    }

    fn insert<T>(&mut self, node: &T, file: FileId, budget: &InputBudget) -> AllocResult<()> {
        storage::map_slot(
            &mut self.locations,
            &(std::ptr::from_ref(node) as usize),
            budget,
        )?;
        self.locations
            .insert(std::ptr::from_ref(node) as usize, file);
        assert_eq!(
            self.locations.get(&(std::ptr::from_ref(node) as usize)),
            Some(&file)
        );
        Ok(())
    }

    pub fn default_value(&self, block: &Block<'_>) -> Option<&tf_eval::Value> {
        self.defaults
            .get(&(std::ptr::from_ref(block) as usize))
            .map(|d| &d.value)
    }

    pub fn type_defaults(&self, block: &Block<'_>) -> Option<&TypeDefaults> {
        self.type_defaults
            .get(&(std::ptr::from_ref(block) as usize))
    }

    pub(super) fn convert_default(
        &mut self,
        block: &Block<'_>,
        value: DefaultValue,
        apply_defaults: bool,
        cx: DefaultContext<'_>,
        errors: &mut Vec<(FileSpan, String)>,
    ) -> AllocResult<()> {
        storage::map_slot(
            &mut self.defaults,
            &(std::ptr::from_ref(block) as usize),
            cx.budget.storage(),
        )?;
        let converted = crate::variable_defaults::convert_default(value, block, apply_defaults, cx)
            .unwrap_or_else(|error| {
                let at = block
                    .body
                    .find_attribute("default")
                    .map(|a| FileSpan::new(self.file(a, cx.at.file), a.span))
                    .unwrap_or(cx.at);
                if error == DefaultError::Invalid {
                    errors.push((
                        at,
                        "variable default is incompatible with its type or nullable constraint"
                            .into(),
                    ));
                }
                DefaultValue::failed(error)
            });
        self.defaults
            .insert(std::ptr::from_ref(block) as usize, converted);
        cx.budget.storage().admit_collection(0)
    }

    fn prepare_default(
        &mut self,
        block: &Block<'_>,
        file: &SourceFile,
        cx: DefaultContext<'_>,
        errors: &mut Vec<(FileSpan, String)>,
    ) -> AllocResult<()> {
        let result = crate::variable_defaults::literal(block, file, cx)
            .and_then(|value| value.map(|v| DefaultValue::literal(v, cx)).transpose());
        match result {
            Ok(Some(value)) => self.convert_default(block, value, true, cx, errors)?,
            Ok(None) => {}
            Err(error) => {
                if error == DefaultError::Invalid {
                    errors.push((cx.at, "invalid variable default".into()));
                }
                storage::map_slot(
                    &mut self.defaults,
                    &(std::ptr::from_ref(block) as usize),
                    cx.budget.storage(),
                )?;
                self.defaults.insert(
                    std::ptr::from_ref(block) as usize,
                    DefaultValue::failed(error),
                );
            }
        }
        cx.budget.storage().admit_collection(0)
    }

    fn body(&mut self, body: &Body<'_>, file: FileId, budget: &InputBudget) -> AllocResult<()> {
        self.insert(body, file, budget)?;
        for item in body.items.iter() {
            match item {
                BodyItem::Attribute(a) => {
                    self.insert(a.as_ref(), file, budget)?;
                    self.insert(&a.value, file, budget)?;
                }
                BodyItem::Block(b) => {
                    self.insert(b.as_ref(), file, budget)?;
                    self.body(&b.body, file, budget)?;
                }
            }
        }
        Ok(())
    }
}
