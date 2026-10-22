//! Ordered override composition. Arena boxes move between bodies without
//! moving their nodes, so source ownership survives attribute/block replacement.
use std::sync::Arc;

use tf_allocator::{AllocResult, Allocator, Vec as ArenaVec};
use tf_ast::{Block, Body, BodyItem, File};
use tf_span::{FileId, FileSpan};

use crate::default_budget::{DefaultContext, DefaultError};
use crate::variable_defaults::{DefaultValue, TypeDefaults};
use crate::{module::is_override, source::SourceFile};

mod merge;
mod origins;
mod overrides;
mod storage;
mod terraform;
mod validation;

pub use origins::Origins;

pub fn compose<'a>(
    alloc: &'a Allocator,
    files: &mut [(Arc<SourceFile>, File<'a>)],
    errors: &mut Vec<(FileSpan, String)>,
    budget: &tf_eval::EvaluationBudget,
) -> AllocResult<Origins> {
    if let Some(error) = alloc.budget().exhaustion() {
        return Err(error);
    }
    let mut origins = Origins::default();
    if !files.iter().any(|(sf, _)| is_override(&sf.path)) {
        return Ok(origins);
    }
    for (sf, ast) in files.iter() {
        validation::body(
            &ast.body,
            sf.id,
            is_override(&sf.path),
            errors,
            budget.storage(),
        )?;
        validation::settings(ast, sf.id, errors);
        for block in ast.body.blocks() {
            origins.prepare_block(block, sf, budget, errors)?;
        }
    }
    for index in 0..files.len() {
        if is_override(&files[index].0.path) {
            overrides::apply(alloc, files, index, &mut origins, errors, budget)?;
        }
    }
    Ok(origins)
}
