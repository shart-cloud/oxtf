use super::*;
use std::collections::HashSet;
use tf_limits::input::InputBudget;

pub(super) fn body(
    body: &Body<'_>,
    file: FileId,
    overriding: bool,
    errors: &mut Vec<(FileSpan, String)>,
    budget: &InputBudget,
) -> AllocResult<()> {
    let mut names = HashSet::new();
    for a in body.attributes() {
        if !storage::set_insert(&mut names, a.key.name, budget)? {
            errors.push((
                FileSpan::new(file, a.span),
                "duplicate attribute in configuration body".into(),
            ));
        }
    }
    let mut singletons = [false; 2];
    for b in body.blocks() {
        let singleton = match b.block_type() {
            "lifecycle" => Some(0),
            "connection" => Some(1),
            _ => None,
        };
        if singleton.is_some_and(|i| std::mem::replace(&mut singletons[i], true)) {
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
        self::body(&b.body, file, overriding, errors, budget)?;
    }
    Ok(())
}

pub(super) fn settings(ast: &File<'_>, file: FileId, errors: &mut Vec<(FileSpan, String)>) {
    let mut seen = [false; 3];
    for setting in ast
        .body
        .blocks()
        .filter(|b| b.block_type() == "terraform")
        .flat_map(|b| b.body.blocks())
    {
        let index = match setting.block_type() {
            "backend" => 0,
            "cloud" => 1,
            "required_providers" => 2,
            _ => continue,
        };
        if std::mem::replace(&mut seen[index], true) {
            errors.push((
                FileSpan::new(file, setting.span),
                "duplicate Terraform settings block in configuration file".into(),
            ));
        }
    }
}
