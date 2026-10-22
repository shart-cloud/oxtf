use super::*;
use merge::{alias, merge_body, merge_named_block, same_header};

pub(super) fn apply<'a>(
    alloc: &'a Allocator,
    files: &mut [(Arc<SourceFile>, File<'a>)],
    index: usize,
    origins: &mut Origins,
    errors: &mut Vec<(FileSpan, String)>,
    budget: &tf_eval::EvaluationBudget,
) -> AllocResult<()> {
    let file = files[index].0.id;
    let mut items = std::mem::replace(&mut files[index].1.body.items, ArenaVec::new_in(alloc));
    for item in items.drain(..) {
        budget.storage().admit_collection(0)?;
        let BodyItem::Block(mut overriding) = item else {
            continue;
        };
        if !prepare(&mut overriding, file, errors) {
            continue;
        }
        match overriding.block_type() {
            "terraform" => {
                if terraform::apply(alloc, files, index, &mut overriding)? {
                    files[index]
                        .1
                        .body
                        .items
                        .push(BodyItem::Block(overriding))?;
                }
            }
            "locals" => apply_locals(files, &mut overriding, file, errors)?,
            _ => {
                let cx = DefaultContext {
                    budget,
                    at: FileSpan::new(file, overriding.span),
                };
                if apply_named(files, index, &mut overriding, origins, errors, cx)? {
                    files[index]
                        .1
                        .body
                        .items
                        .push(BodyItem::Block(overriding))?;
                }
            }
        }
    }
    Ok(())
}

fn prepare(block: &mut Block<'_>, file: FileId, errors: &mut Vec<(FileSpan, String)>) -> bool {
    if matches!(block.block_type(), "moved" | "removed" | "import" | "check") {
        errors.push((
            FileSpan::new(file, block.span),
            "this block type cannot be composed in an override file".into(),
        ));
        return false;
    }
    if matches!(
        block.block_type(),
        "resource" | "data" | "module" | "output"
    ) {
        if let Some(a) = block.body.find_attribute("depends_on")
            && !matches!(&a.value, tf_ast::Expression::Tuple(t) if t.elements.is_empty())
        {
            errors.push((
                FileSpan::new(file, a.span),
                "depends_on cannot be overridden".into(),
            ));
        }
        // Terraform treats an empty override list as unspecified.
        block
            .body
            .items
            .retain(|i| !matches!(i, BodyItem::Attribute(a) if a.key.name == "depends_on"));
    }
    if block.block_type() == "module" {
        block.body.items.retain(|item| match item {
            BodyItem::Attribute(a) if a.key.name == "providers" => {
                !matches!(&a.value, tf_ast::Expression::Object(o) if o.items.is_empty())
            }
            _ => true,
        });
    }
    if block.block_type() == "resource" {
        // Terraform 1.16.1 does not merge replacement triggers.
        for item in block.body.items.iter_mut() {
            if let BodyItem::Block(b) = item
                && b.block_type() == "lifecycle"
            {
                b.body.items.retain(|item| {
                    !matches!(item, BodyItem::Attribute(a) if a.key.name == "replace_triggered_by")
                });
            }
        }
    }
    true
}

fn apply_locals<'a>(
    files: &mut [(Arc<SourceFile>, File<'a>)],
    overriding: &mut Block<'a>,
    file: FileId,
    errors: &mut Vec<(FileSpan, String)>,
) -> AllocResult<()> {
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
            base.body
                .items
                .retain(|i| !matches!(i, BodyItem::Attribute(old) if old.key.name == a.key.name));
            base.body.items.push(BodyItem::Attribute(a))?;
        } else {
            errors.push((
                FileSpan::new(file, a.span),
                "override has no matching base local value".into(),
            ));
        }
    }
    Ok(())
}

/// Return true only when an unmatched, unaliased provider must remain in this file.
fn apply_named<'a>(
    files: &mut [(Arc<SourceFile>, File<'a>)],
    index: usize,
    overriding: &mut Block<'a>,
    origins: &mut Origins,
    errors: &mut Vec<(FileSpan, String)>,
    cx: DefaultContext<'_>,
) -> AllocResult<bool> {
    let target = files
        .iter_mut()
        .enumerate()
        .filter(|(fi, (sf, _))| *fi <= index || !is_override(&sf.path))
        .flat_map(|(_, (_, ast))| ast.body.items.iter_mut())
        .find_map(|item| match item {
            BodyItem::Block(b) if same_header(b, overriding) => Some(b),
            _ => None,
        });
    let Some(base) = target else {
        if overriding.block_type() == "provider" && alias(overriding).is_none() {
            return Ok(true);
        }
        errors.push((cx.at, "override has no matching base declaration".into()));
        return Ok(false);
    };
    let default = if base.block_type() == "variable" {
        origins
            .defaults
            .get(&(std::ptr::from_ref(overriding) as usize))
            .or_else(|| {
                origins
                    .defaults
                    .get(&(std::ptr::from_ref(base.as_ref()) as usize))
            })
            .map(|value| {
                value
                    .clone_with_context(cx)
                    .unwrap_or_else(DefaultValue::failed)
            })
    } else {
        None
    };
    if base.block_type() == "resource" {
        merge_named_block(&mut base.body, &mut overriding.body, "lifecycle")?;
    }
    merge_body(&mut base.body, &mut overriding.body)?;
    if let Some(value) = default {
        origins.convert_default(base, value, false, cx, errors)?;
    }
    Ok(false)
}
