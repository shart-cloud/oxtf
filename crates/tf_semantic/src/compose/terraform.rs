use super::*;
use merge::{merge_body, merge_named_block};

/// Return true when there is no existing settings body to merge into.
pub(super) fn apply<'a>(
    alloc: &'a Allocator,
    files: &mut [(Arc<SourceFile>, File<'a>)],
    index: usize,
    overriding: &mut Block<'a>,
) -> AllocResult<bool> {
    let Some((fi, bi)) = consolidate(alloc, files, index)? else {
        return Ok(true);
    };
    let BodyItem::Block(base) = &mut files[fi].1.body.items[bi] else {
        unreachable!()
    };
    merge_named_block(&mut base.body, &mut overriding.body, "required_providers")?;
    if overriding
        .body
        .blocks()
        .any(|b| matches!(b.block_type(), "backend" | "cloud"))
    {
        base.body.items.retain(|item| {
            !matches!(item, BodyItem::Block(b) if matches!(b.block_type(), "backend" | "cloud"))
        });
    }
    merge_body(&mut base.body, &mut overriding.body)?;
    Ok(false)
}

fn consolidate<'a>(
    alloc: &'a Allocator,
    files: &mut [(Arc<SourceFile>, File<'a>)],
    index: usize,
) -> AllocResult<Option<(usize, usize)>> {
    let mut first = None;
    for fi in 0..files.len() {
        if fi > index && is_override(&files[fi].0.path) {
            continue;
        }
        for bi in 0..files[fi].1.body.items.len() {
            let BodyItem::Block(block) = &mut files[fi].1.body.items[bi] else {
                continue;
            };
            if block.block_type() != "terraform" {
                continue;
            }
            let Some((base_file, base_block)) = first else {
                first = Some((fi, bi));
                continue;
            };
            // Only nested items move, so outer file/block indices stay valid.
            assert!((base_file, base_block) < (fi, bi));
            let mut extra = std::mem::replace(&mut block.body.items, ArenaVec::new_in(alloc));
            let BodyItem::Block(base) = &mut files[base_file].1.body.items[base_block] else {
                unreachable!()
            };
            base.body.items.extend(extra.drain(..))?;
            assert!(extra.is_empty());
        }
    }
    Ok(first)
}
