//! Ordered override composition. Arena boxes move between bodies without
//! moving their nodes, so source ownership survives attribute/block replacement.
use std::collections::HashSet;
use std::sync::Arc;

use rustc_hash::FxHashMap;
use tf_allocator::{Allocator, Vec as ArenaVec};
use tf_ast::{Block, Body, BodyItem, File};
use tf_span::{FileId, FileSpan};

use crate::variable_defaults::{DefaultValue, TypeDefaults};
use crate::{module::is_override, source::SourceFile};

/// Source ownership for composed nodes. Empty for modules without overrides.
/// Keys are addresses of immutable arena nodes; no pointer is dereferenced.
#[derive(Default)]
pub struct Origins {
    locations: FxHashMap<usize, FileId>,
    defaults: FxHashMap<usize, DefaultValue>,
    type_defaults: FxHashMap<usize, TypeDefaults>,
}

impl Origins {
    pub fn file<T>(&self, node: &T, fallback: FileId) -> FileId {
        self.locations
            .get(&(std::ptr::from_ref(node) as usize))
            .copied()
            .unwrap_or(fallback)
    }

    fn insert<T>(&mut self, node: &T, file: FileId) {
        self.locations
            .insert(std::ptr::from_ref(node) as usize, file);
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

    fn convert_default(
        &mut self,
        block: &Block<'_>,
        value: DefaultValue,
        apply_defaults: bool,
        file: FileId,
        errors: &mut Vec<(FileSpan, String)>,
    ) {
        let converted = crate::variable_defaults::convert_default(value, block, apply_defaults)
            .unwrap_or_else(|()| {
                let at = block
                    .body
                    .find_attribute("default")
                    .map(|a| FileSpan::new(self.file(a, file), a.span))
                    .unwrap_or(FileSpan::new(file, block.span));
                errors.push((
                    at,
                    "variable default is incompatible with its type or nullable constraint".into(),
                ));
                DefaultValue::literal(tf_eval::Value::error("invalid variable default"))
            });
        self.defaults
            .insert(std::ptr::from_ref(block) as usize, converted);
    }

    fn body(&mut self, body: &Body<'_>, file: FileId) {
        self.insert(body, file);
        for item in body.items.iter() {
            match item {
                BodyItem::Attribute(a) => {
                    self.insert(a.as_ref(), file);
                    self.insert(&a.value, file);
                }
                BodyItem::Block(b) => {
                    self.insert(b.as_ref(), file);
                    self.body(&b.body, file);
                }
            }
        }
    }
}

pub fn compose<'a>(
    alloc: &'a Allocator,
    files: &mut [(Arc<SourceFile>, File<'a>)],
    errors: &mut Vec<(FileSpan, String)>,
) -> Origins {
    let mut origins = Origins::default();
    if !files.iter().any(|(sf, _)| is_override(&sf.path)) {
        return origins;
    }
    for (sf, f) in files.iter() {
        validate_body(&f.body, sf.id, is_override(&sf.path), errors);
        let mut settings = HashSet::new();
        for setting in f
            .body
            .blocks()
            .filter(|b| b.block_type() == "terraform")
            .flat_map(|b| b.body.blocks())
        {
            if matches!(
                setting.block_type(),
                "backend" | "cloud" | "required_providers"
            ) && !settings.insert(setting.block_type())
            {
                errors.push((
                    FileSpan::new(sf.id, setting.span),
                    "duplicate Terraform settings block in configuration file".into(),
                ));
            }
        }
        for b in f.body.blocks() {
            origins.insert(b, sf.id);
            origins.body(&b.body, sf.id);
            if b.block_type() == "variable"
                && let Some(ty) = b.body.find_attribute("type")
                && !crate::variable_defaults::valid_type(&ty.value)
            {
                errors.push((
                    FileSpan::new(sf.id, ty.span),
                    "invalid variable type constraint".into(),
                ));
            }
            if b.block_type() == "variable" && !is_override(&sf.path) {
                let defaults = match b.body.find_attribute("type") {
                    Some(ty) => TypeDefaults::from_type(&ty.value).unwrap_or_else(|()| {
                        errors.push((
                            FileSpan::new(sf.id, ty.span),
                            "invalid optional attribute default".into(),
                        ));
                        TypeDefaults::default()
                    }),
                    None => TypeDefaults::default(),
                };
                origins
                    .type_defaults
                    .insert(std::ptr::from_ref(b) as usize, defaults);
            }
            if b.block_type() == "variable"
                && let Some(value) = crate::variable_defaults::literal(b, sf)
            {
                origins.convert_default(b, DefaultValue::literal(value), true, sf.id, errors);
            }
        }
    }
    for index in 0..files.len() {
        if !is_override(&files[index].0.path) {
            continue;
        }
        let file = files[index].0.id;
        let mut items = std::mem::replace(&mut files[index].1.body.items, ArenaVec::new_in(alloc));
        for item in items.drain(..) {
            let BodyItem::Block(mut overriding) = item else {
                continue;
            };
            if matches!(
                overriding.block_type(),
                "moved" | "removed" | "import" | "check"
            ) {
                errors.push((
                    FileSpan::new(file, overriding.span),
                    "this block type cannot be composed in an override file".into(),
                ));
                continue;
            }
            if matches!(
                overriding.block_type(),
                "resource" | "data" | "module" | "output"
            ) {
                if let Some(a) = overriding.body.find_attribute("depends_on")
                    && !matches!(&a.value, tf_ast::Expression::Tuple(t) if t.elements.is_empty())
                {
                    errors.push((
                        FileSpan::new(file, a.span),
                        "depends_on cannot be overridden".into(),
                    ));
                }
                // Terraform treats an empty override list as unspecified.
                overriding
                    .body
                    .items
                    .retain(|i| !matches!(i, BodyItem::Attribute(a) if a.key.name == "depends_on"));
            }
            if overriding.block_type() == "module" {
                overriding.body.items.retain(|i| !matches!(i, BodyItem::Attribute(a)
                    if a.key.name == "providers" && matches!(&a.value, tf_ast::Expression::Object(o) if o.items.is_empty())));
            }
            if overriding.block_type() == "resource" {
                // Terraform 1.16.1 does not merge replacement triggers.
                for item in overriding.body.items.iter_mut() {
                    if let BodyItem::Block(b) = item
                        && b.block_type() == "lifecycle"
                    {
                        b.body.items.retain(|i| !matches!(i, BodyItem::Attribute(a) if a.key.name == "replace_triggered_by"));
                    }
                }
            }
            if overriding.block_type() == "terraform" {
                let positions: Vec<_> = files
                    .iter()
                    .enumerate()
                    .filter(|(fi, (sf, _))| *fi <= index || !is_override(&sf.path))
                    .flat_map(|(fi, (_, f))| {
                        f.body
                            .items
                            .iter()
                            .enumerate()
                            .filter_map(move |(bi, item)| {
                                matches!(item, BodyItem::Block(b) if b.block_type() == "terraform")
                                    .then_some((fi, bi))
                            })
                    })
                    .collect();
                if let Some(&(fi, bi)) = positions.first() {
                    // Settings are module-wide, independent of the terraform
                    // block/file that originally contained them.
                    for &(other_file, other_block) in &positions[1..] {
                        let BodyItem::Block(b) = &mut files[other_file].1.body.items[other_block]
                        else {
                            unreachable!()
                        };
                        let mut extra =
                            std::mem::replace(&mut b.body.items, ArenaVec::new_in(alloc));
                        let BodyItem::Block(base) = &mut files[fi].1.body.items[bi] else {
                            unreachable!()
                        };
                        base.body.items.extend(extra.drain(..));
                    }
                    let BodyItem::Block(base) = &mut files[fi].1.body.items[bi] else {
                        unreachable!()
                    };
                    merge_named_block(&mut base.body, &mut overriding.body, "required_providers");
                    if overriding
                        .body
                        .blocks()
                        .any(|b| matches!(b.block_type(), "backend" | "cloud"))
                    {
                        base.body.items.retain(|i| !matches!(i, BodyItem::Block(b) if matches!(b.block_type(), "backend" | "cloud")));
                    }
                    merge_body(&mut base.body, &mut overriding.body);
                } else {
                    files[index].1.body.items.push(BodyItem::Block(overriding));
                }
                continue;
            }
            if overriding.block_type() == "locals" {
                for item in overriding.body.items.drain(..) {
                    let BodyItem::Attribute(a) = item else {
                        continue;
                    };
                    let target = files
                        .iter_mut()
                        .filter(|(sf, _)| !is_override(&sf.path))
                        .flat_map(|(_, f)| f.body.items.iter_mut())
                        .find_map(|i| match i {
                            BodyItem::Block(b)
                                if b.block_type() == "locals"
                                    && b.body.find_attribute(&a.key.name).is_some() =>
                            {
                                Some(b)
                            }
                            _ => None,
                        });
                    if let Some(base) = target {
                        base.body.items.retain(|i| !matches!(i, BodyItem::Attribute(old) if old.key.name == a.key.name));
                        base.body.items.push(BodyItem::Attribute(a));
                    } else {
                        errors.push((
                            FileSpan::new(file, a.span),
                            "override has no matching base local value".into(),
                        ));
                    }
                }
                continue;
            }
            let target = files
                .iter()
                .enumerate()
                .filter(|(fi, (sf, _))| *fi <= index || !is_override(&sf.path))
                .find_map(|(fi, (_, ast))| {
                    ast.body.items.iter().position(|item| {
                    matches!(item, BodyItem::Block(b) if same_header(b, &overriding))
                }).map(|bi| (fi, bi))
                });
            if let Some((fi, bi)) = target {
                let BodyItem::Block(base) = &mut files[fi].1.body.items[bi] else {
                    unreachable!()
                };
                let default = if base.block_type() == "variable" {
                    origins
                        .defaults
                        .get(&(std::ptr::from_ref(overriding.as_ref()) as usize))
                        .or_else(|| {
                            origins
                                .defaults
                                .get(&(std::ptr::from_ref(base.as_ref()) as usize))
                        })
                        .cloned()
                } else {
                    None
                };
                if base.block_type() == "resource" {
                    merge_named_block(&mut base.body, &mut overriding.body, "lifecycle");
                }
                merge_body(&mut base.body, &mut overriding.body);
                if let Some(value) = default {
                    origins.convert_default(base, value, false, file, errors);
                }
            } else {
                if overriding.block_type() == "provider" && alias(&overriding).is_none() {
                    files[index].1.body.items.push(BodyItem::Block(overriding));
                } else {
                    errors.push((
                        FileSpan::new(file, overriding.span),
                        "override has no matching base declaration".into(),
                    ));
                }
            }
        }
    }
    origins
}

fn validate_body(
    body: &Body<'_>,
    file: FileId,
    overriding: bool,
    errors: &mut Vec<(FileSpan, String)>,
) {
    let mut names = HashSet::new();
    for a in body.attributes() {
        if !names.insert(a.key.name) {
            errors.push((
                FileSpan::new(file, a.span),
                "duplicate attribute in configuration body".into(),
            ));
        }
    }
    let mut singletons = HashSet::new();
    for b in body.blocks() {
        if matches!(b.block_type(), "lifecycle" | "connection")
            && !singletons.insert(b.block_type())
        {
            errors.push((
                FileSpan::new(file, b.span),
                "duplicate singleton block".into(),
            ));
        }
        if overriding
            && matches!(
                b.block_type(),
                "validation" | "precondition" | "postcondition"
            )
        {
            errors.push((
                FileSpan::new(file, b.span),
                "validation conditions cannot be overridden".into(),
            ));
        }
        validate_body(&b.body, file, overriding, errors);
    }
}

fn same_header(a: &Block<'_>, b: &Block<'_>) -> bool {
    a.block_type() == b.block_type()
        && a.labels
            .iter()
            .map(|l| l.value.as_str())
            .eq(b.labels.iter().map(|l| l.value.as_str()))
        && (a.block_type() != "provider" || alias(a) == alias(b))
}

fn alias<'a>(b: &'a Block<'_>) -> Option<&'a str> {
    b.body
        .find_attribute("alias")
        .and_then(|a| a.value.as_string_literal())
}

fn merge_body<'a>(base: &mut Body<'a>, overriding: &mut Body<'a>) {
    base.items.retain(|item| match item {
        BodyItem::Attribute(a) => !overriding.attributes().any(|o| o.key.name == a.key.name),
        BodyItem::Block(b) => !overriding.blocks().any(|o| block_type(o) == block_type(b)),
    });
    base.items.extend(overriding.items.drain(..));
}

fn block_type<'a>(block: &'a Block<'_>) -> &'a str {
    if block.block_type() == "dynamic" {
        block.label(0).unwrap_or("dynamic")
    } else {
        block.block_type()
    }
}

fn merge_named_block<'a>(base: &mut Body<'a>, overriding: &mut Body<'a>, name: &str) {
    let Some(base) = base.items.iter_mut().find_map(|item| match item {
        BodyItem::Block(b) if b.block_type() == name => Some(b),
        _ => None,
    }) else {
        return;
    };
    let Some(index) = overriding
        .items
        .iter()
        .position(|item| matches!(item, BodyItem::Block(b) if b.block_type() == name))
    else {
        return;
    };
    let BodyItem::Block(mut overriding) = overriding.items.remove(index) else {
        unreachable!()
    };
    if name == "lifecycle" {
        let ignores_all = base.body.find_attribute("ignore_changes").is_some_and(
            |a| matches!(&a.value, tf_ast::Expression::Variable(v) if v.name == "all"),
        );
        overriding.body.items.retain(|item| !matches!(item,
            BodyItem::Attribute(a) if a.key.name == "ignore_changes"
                && (ignores_all || matches!(&a.value, tf_ast::Expression::Tuple(t) if t.elements.is_empty()))
        ));
    }
    merge_body(&mut base.body, &mut overriding.body);
}
