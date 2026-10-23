use super::*;

pub(super) enum CollectionItems<'v> {
    List(&'v Value, std::iter::Enumerate<std::slice::Iter<'v, Value>>),
    Object(
        &'v Value,
        std::collections::btree_map::Iter<'v, Arc<str>, Value>,
    ),
}

impl Iterator for CollectionItems<'_> {
    type Item = (Value, Value);
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::List(parent, items) => items.next().map(|(index, value)| {
                let value = value.child_of(parent);
                let key = if value.as_str().is_some() {
                    value.clone()
                } else {
                    Value::number(index as f64).inherit_sensitive(parent)
                };
                (key, value)
            }),
            Self::Object(parent, items) => items.next().map(|(key, value)| {
                (
                    Value::string(key.clone()).inherit_sensitive(parent),
                    value.child_of(parent),
                )
            }),
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for CollectionItems<'_> {
    fn len(&self) -> usize {
        match self {
            Self::List(_, items) => items.len(),
            Self::Object(_, items) => items.len(),
        }
    }
}

pub(super) fn collection_items(value: &Value) -> Option<CollectionItems<'_>> {
    match &value.kind {
        Kind::Known(Known::List(items)) => {
            Some(CollectionItems::List(value, items.iter().enumerate()))
        }
        Kind::Known(Known::Object(items)) => Some(CollectionItems::Object(value, items.iter())),
        _ => None,
    }
}

pub(super) struct InstResolver<'x, 'a, 'o> {
    pub(super) an: &'x Analyzer<'a, 'o>,
    pub(super) inst: usize,
}

impl<'a> Resolver<'a> for InstResolver<'_, 'a, '_> {
    fn call(&self, name: &str, args: Vec<Value>, budget: &tf_eval::EvaluationBudget) -> Value {
        let inst = self.an.inst(self.inst);
        let boundary = inst
            .package
            .as_ref()
            .and_then(|p| p.package_root.as_deref());
        crate::file_functions::call(
            self.an.files,
            &self.an.root_dir,
            boundary,
            name,
            args,
            false,
            budget,
        )
    }

    fn resolve(
        &self,
        ev: &Evaluator<'_, 'a>,
        sc: Scope<'_>,
        root: &'a str,
        _span: Span,
        ops: &'a [TraversalOperator<'a>],
    ) -> (Value, usize) {
        let an = self.an;
        let a0 = ops.first().and_then(|o| o.attr_name());
        match root {
            "var" => match a0 {
                Some(n) => (an.var_value(self.inst, n), 1),
                None => (Value::error("invalid reference to var"), 0),
            },
            "local" => match a0 {
                Some(n) => (an.local_value(self.inst, n), 1),
                None => (Value::error("invalid reference to local"), 0),
            },
            "path" => {
                let inst = an.inst(self.inst);
                let rel = |p: &Path| {
                    crate::source::relative_to(p, &an.root_dir)
                        .display()
                        .to_string()
                };
                match a0 {
                    Some("module") => (Value::string(rel(&inst.def.dir)), 1),
                    Some("root") | Some("cwd") => (Value::string("."), 1),
                    _ => (Value::error("invalid path reference"), 0),
                }
            }
            "terraform" => (Value::other("terraform.workspace"), ops.len().min(1)),
            "count" | "each" | "self" => (
                Value::other(format!("{root} (outside its context)")),
                ops.len().min(1),
            ),
            "module" => an
                .module_ref(self.inst, ops, ev, sc)
                .unwrap_or_else(|v| (v, ops.len())),
            "data" => match a0 {
                Some(ty) => {
                    let (v, used) = an
                        .resource_ref(self.inst, Mode::Data, ty, &ops[1..], ev, sc)
                        .unwrap_or_else(|v| (v, ops.len() - 1));
                    (v, used + 1)
                }
                None => (Value::error("invalid data reference"), 0),
            },
            ty => an
                .resource_ref(self.inst, Mode::Managed, ty, ops, ev, sc)
                .unwrap_or_else(|v| (v, ops.len())),
        }
    }
}
