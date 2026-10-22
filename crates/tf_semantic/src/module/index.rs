use super::*;
use std::hash::Hash;
use tf_limits::input::InputBudget;

pub(super) fn build<'a>(def: &mut ModuleDef<'a>, budget: &InputBudget) -> Build<()> {
    tf_eval::collections::admit::<u8>(0, budget)?;
    // Copy only the arena reference, so indexing needs no second file-list allocation.
    for i in 0..def.files.len() {
        let file = def.files[i].0.id;
        let ast = def.files[i].1;
        for block in ast.body.blocks() {
            index_block(def, file, block, budget)?;
        }
    }
    Ok(())
}

pub(super) fn discard(def: &mut ModuleDef<'_>) {
    def.variables.clear();
    def.locals.clear();
    def.resources.clear();
    def.module_calls.clear();
    def.outputs.clear();
    def.var_index.clear();
    def.local_index.clear();
    def.res_index.clear();
    def.call_index.clear();
    def.output_index.clear();
    def.origins = crate::compose::Origins::default();
    assert!(def.references.is_empty());
}

fn slot<K: Eq + Hash, V>(
    index: &mut HashMap<K, usize>,
    items: &mut Vec<V>,
    key: K,
    budget: &InputBudget,
) -> Build<()> {
    storage::reserve(items, 1, budget)?;
    if !index.contains_key(&key) {
        storage::hash_slot(index, budget)?;
        index.insert(key, items.len());
    }
    assert!(items.capacity() > items.len());
    Ok(())
}

fn index_block<'a>(
    def: &mut ModuleDef<'a>,
    file: FileId,
    b: &'a Block<'a>,
    budget: &InputBudget,
) -> Build<()> {
    let duplicate = match (b.block_type(), b.label(0), b.label(1)) {
        ("variable", Some(n), _) => def.var_index.contains_key(n),
        ("module", Some(n), _) => def.call_index.contains_key(n),
        ("output", Some(n), _) => def.output_index.contains_key(n),
        ("resource", Some(t), Some(n)) => def.res_index.contains_key(&(Mode::Managed, t, n)),
        ("data", Some(t), Some(n)) => def.res_index.contains_key(&(Mode::Data, t, n)),
        _ => false,
    };
    if duplicate {
        def.parse_errors.push((
            FileSpan::new(file, b.span),
            "duplicate declaration in ordinary configuration".into(),
        ));
    }
    if matches!(b.block_type(), "resource" | "data" | "module")
        && b.body.find_attribute("count").is_some()
        && let Some(each) = b.body.find_attribute("for_each")
    {
        def.parse_errors.push((
            FileSpan::new(def.origins.file(each, file), each.span),
            "count and for_each cannot both be set".into(),
        ));
    }
    match b.block_type() {
        "variable" => index_variable(def, file, b, budget),
        "locals" => index_locals(def, file, b, budget),
        "resource" | "data" => index_resource(def, file, b, budget),
        "module" => index_call(def, file, b, budget),
        "output" => index_output(def, file, b, budget),
        _ => Ok(()),
    }
}

fn index_variable<'a>(
    def: &mut ModuleDef<'a>,
    file: FileId,
    b: &'a Block<'a>,
    budget: &InputBudget,
) -> Build<()> {
    if let Some(name) = b.label(0) {
        slot(&mut def.var_index, &mut def.variables, name, budget)?;
        def.variables.push(VarDecl {
            name,
            block: b,
            file,
            default: b.body.find_attribute("default"),
            default_value: def.origins.default_value(b).cloned(),
            ty: b.body.find_attribute("type").map(|a| &a.value),
            non_nullable: b
                .body
                .find_attribute("nullable")
                .is_some_and(|a| matches!(&a.value, Expression::Bool(x) if !x.value)),
        });
    }
    Ok(())
}

fn index_locals<'a>(
    def: &mut ModuleDef<'a>,
    file: FileId,
    b: &'a Block<'a>,
    budget: &InputBudget,
) -> Build<()> {
    for a in b.body.attributes() {
        let name = a.key.name.as_str();
        if def.local_index.contains_key(name) {
            def.parse_errors.push((
                FileSpan::new(def.origins.file(a, file), a.span),
                "duplicate local value in ordinary configuration".into(),
            ));
        }
        slot(&mut def.local_index, &mut def.locals, name, budget)?;
        def.locals.push(LocalDecl {
            name,
            attr: a,
            file: def.origins.file(a, file),
        });
    }
    Ok(())
}

fn index_resource<'a>(
    def: &mut ModuleDef<'a>,
    file: FileId,
    b: &'a Block<'a>,
    budget: &InputBudget,
) -> Build<()> {
    let mode = if b.block_type() == "resource" {
        Mode::Managed
    } else {
        Mode::Data
    };
    if let (Some(ty), Some(name)) = (b.label(0), b.label(1)) {
        let schema = match mode {
            Mode::Managed => tf_schema::lookup_resource(ty),
            Mode::Data => tf_schema::lookup_data_source(ty),
        };
        slot(
            &mut def.res_index,
            &mut def.resources,
            (mode, ty, name),
            budget,
        )?;
        def.resources.push(ResourceDecl {
            mode,
            ty,
            name,
            block: b,
            file,
            schema,
        });
    }
    Ok(())
}

fn index_call<'a>(
    def: &mut ModuleDef<'a>,
    file: FileId,
    b: &'a Block<'a>,
    budget: &InputBudget,
) -> Build<()> {
    if let Some(name) = b.label(0) {
        slot(&mut def.call_index, &mut def.module_calls, name, budget)?;
        let source = match b
            .body
            .find_attribute("source")
            .and_then(|a| a.value.as_string_literal())
        {
            Some(s) if s.starts_with("./") || s.starts_with("../") || s == "." || s == ".." => {
                ModuleSource::Local(normalize(&def.dir.join(s)))
            }
            Some(s) => ModuleSource::Remote(s.to_string()),
            None => ModuleSource::Invalid,
        };
        def.module_calls.push(ModuleCall {
            name,
            block: b,
            file,
            source,
        });
    }
    Ok(())
}

fn index_output<'a>(
    def: &mut ModuleDef<'a>,
    file: FileId,
    b: &'a Block<'a>,
    budget: &InputBudget,
) -> Build<()> {
    if let Some(name) = b.label(0) {
        slot(&mut def.output_index, &mut def.outputs, name, budget)?;
        def.outputs.push(OutputDecl {
            name,
            block: b,
            file,
            value: b.body.find_attribute("value"),
        });
    }
    Ok(())
}
