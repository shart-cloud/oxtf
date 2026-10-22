use super::*;
use tf_limits::{Limits, Resource};

const SOURCE: &str = r#"
variable "items" {}
locals {
    x = [for k, v in var.items : "${k}:${v.name}:${local.after}" if v.ok]
    y = "%{ for k,v in var.items }${k}-${v}%{ endfor }-${v}"
    after = 1
}
resource "test_node" "r" {
    dynamic "child" {
        for_each = var.items
        iterator = it
        content { x = it.value }
    }
    x = it.value
}
output "r" { value = test_node.r }
"#;

fn files() -> FileTable {
    FileTable::with_overlay([(
        Path::new("/nonexistent/oxtf-references/main.tf").to_path_buf(),
        Arc::from(SOURCE),
    )])
}

#[test]
fn every_reference_capacity_boundary_is_atomic_and_keeps_lexical_meaning() {
    let files = files();
    let alloc = files.allocator();
    let mut def = load_module(&alloc, &files, Path::new("/nonexistent/oxtf-references"));
    assert!(def.parse_errors.is_empty());
    let expected = def.references.clone();
    assert!(
        expected
            .iter()
            .any(|r| r.to == SymbolRef::Implicit("v".into()))
    );
    assert!(
        expected
            .iter()
            .any(|r| r.to == SymbolRef::Unresolved("v".into()))
    );
    assert!(
        expected
            .iter()
            .any(|r| r.to == SymbolRef::Implicit("it".into()))
    );
    assert!(
        expected
            .iter()
            .any(|r| r.to == SymbolRef::Unresolved("it".into()))
    );
    let full = InputBudget::new(Limits::default());
    collect(&mut def, &full).unwrap();
    let cost = full.stats().collection_bytes;
    for allowance in 1..=cost + 1 {
        def.references = Arc::new(Vec::new());
        let budget = InputBudget::new(Limits::default().with_collection_bytes(allowance).unwrap());
        let result = collect(&mut def, &budget);
        if allowance < cost {
            assert!(result.is_err());
            assert!(def.references.is_empty());
            assert_eq!(
                budget.exhaustion().unwrap().resource,
                Resource::CollectionBytes
            );
        } else {
            result.unwrap();
            assert_eq!(def.references.len(), expected.len());
            for (actual, expected) in def.references.iter().zip(expected.iter()) {
                assert_eq!(actual.from, expected.from);
                assert_eq!(actual.to, expected.to);
                assert_eq!(actual.at, expected.at);
            }
        }
        assert!(budget.stats().collection_bytes <= allowance);
    }
}

#[test]
fn reference_slot_refusal_precedes_owned_symbol_copy() {
    let files = files();
    let store = crate::ModuleStore::new();
    let def = store
        .module(&files, Path::new("/nonexistent/oxtf-references"))
        .unwrap();
    let long = "x".repeat(1_000_000);
    let budget = InputBudget::new(Limits::default().with_collection_bytes(1).unwrap());
    let mut collector = RefCollector {
        file: FileId(0),
        origins: &def.origins,
        from: SymbolRef::Local("x".into()),
        bound: Vec::new(),
        out: Vec::new(),
        vars: &def.var_index,
        locals: &def.local_index,
        res: &def.res_index,
        calls: &def.call_index,
        budget: &budget,
    };
    let (result, bytes) =
        crate::test_allocations::measure(|| collector.root(&long, &[], Span::EMPTY));
    assert!(result.is_err());
    assert!(collector.out.is_empty());
    assert!(
        bytes < 4096,
        "allocated {bytes} bytes before refusing a reference slot"
    );
}

#[test]
fn binding_storage_is_required_even_when_a_comprehension_has_no_reference_edges() {
    let root = Path::new("/nonexistent/oxtf-no-edges");
    let files = FileTable::with_overlay([(
        root.join("main.tf"),
        Arc::from("locals { x=[for n in [] : 1] }"),
    )]);
    let alloc = files.allocator();
    let mut def = load_module(&alloc, &files, root);
    let full = InputBudget::new(Limits::default());
    collect(&mut def, &full).unwrap();
    assert!(def.references.is_empty());
    let cost = full.stats().collection_bytes;
    assert!(cost > 1);
    let budget = InputBudget::new(Limits::default().with_collection_bytes(cost - 1).unwrap());
    assert!(collect(&mut def, &budget).is_err());
    assert!(def.references.is_empty());
    assert_eq!(
        budget.exhaustion().unwrap().resource,
        Resource::CollectionBytes
    );
}
