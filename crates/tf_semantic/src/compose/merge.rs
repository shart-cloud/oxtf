use super::*;

pub(super) fn same_header(a: &Block<'_>, b: &Block<'_>) -> bool {
    a.block_type() == b.block_type()
        && a.labels
            .iter()
            .map(|l| l.value.as_str())
            .eq(b.labels.iter().map(|l| l.value.as_str()))
        && (a.block_type() != "provider" || alias(a) == alias(b))
}

pub(super) fn alias<'a>(b: &'a Block<'_>) -> Option<&'a str> {
    b.body
        .find_attribute("alias")
        .and_then(|a| a.value.as_string_literal())
}

pub(super) fn merge_body<'a>(
    base: &mut Body<'a>,
    overriding: &mut Body<'a>,
) -> tf_allocator::AllocResult<()> {
    base.items.retain(|item| match item {
        BodyItem::Attribute(a) => !overriding.attributes().any(|o| o.key.name == a.key.name),
        BodyItem::Block(b) => !overriding.blocks().any(|o| block_type(o) == block_type(b)),
    });
    base.items.extend(overriding.items.drain(..))?;

    Ok(())
}

pub(super) fn block_type<'a>(block: &'a Block<'_>) -> &'a str {
    if block.block_type() == "dynamic" {
        block.label(0).unwrap_or("dynamic")
    } else {
        block.block_type()
    }
}

pub(super) fn merge_named_block<'a>(
    base: &mut Body<'a>,
    overriding: &mut Body<'a>,
    name: &str,
) -> tf_allocator::AllocResult<()> {
    let Some(base) = base.items.iter_mut().find_map(|item| match item {
        BodyItem::Block(b) if b.block_type() == name => Some(b),
        _ => None,
    }) else {
        return Ok(());
    };
    let Some(index) = overriding
        .items
        .iter()
        .position(|item| matches!(item, BodyItem::Block(b) if b.block_type() == name))
    else {
        return Ok(());
    };
    let BodyItem::Block(mut overriding) = overriding.items.remove(index) else {
        unreachable!()
    };
    if name == "lifecycle" {
        let ignores_all = base.body.find_attribute("ignore_changes").is_some_and(
            |a| matches!(&a.value, tf_ast::Expression::Variable(v) if v.name == "all"),
        );
        overriding.body.items.retain(|item| match item {
            BodyItem::Attribute(a) if a.key.name == "ignore_changes" => {
                !ignores_all
                    && !matches!(&a.value, tf_ast::Expression::Tuple(t) if t.elements.is_empty())
            }
            _ => true,
        });
    }
    merge_body(&mut base.body, &mut overriding.body)?;

    Ok(())
}
