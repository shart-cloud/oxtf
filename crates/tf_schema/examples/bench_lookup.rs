//! Startup / lookup cost of the embedded schema IR.
//!
//! cargo run --release -p tf_schema --example bench_lookup
use std::time::Instant;

fn main() {
    let t0 = Instant::now();
    let sg = tf_schema::lookup_resource("aws_security_group").unwrap();
    let first = t0.elapsed();
    assert!(sg.attribute("ingress").is_some());

    let t1 = Instant::now();
    let db = tf_schema::lookup_resource("aws_db_instance").unwrap();
    let second = t1.elapsed();
    assert!(db.attribute("storage_encrypted").unwrap().is_bool());

    // Largest record in the blob (220 KB of postcard; deeply nested wafv2 statements).
    let tw = Instant::now();
    let waf = tf_schema::lookup_resource("aws_wafv2_web_acl_rule").unwrap();
    let largest = tw.elapsed();
    assert!(!waf.block_types().is_empty());

    let t2 = Instant::now();
    let names: Vec<_> = tf_schema::entries().collect();
    let mut attrs = 0usize;
    for (name, kind, _) in &names {
        attrs += tf_schema::lookup(*kind, name).unwrap().attributes().len();
    }
    let all_cold = t2.elapsed();

    let t3 = Instant::now();
    let mut hits = 0usize;
    for (name, kind, _) in &names {
        let s = tf_schema::lookup(*kind, name).unwrap();
        hits += s.attribute("id").is_some() as usize;
    }
    let all_warm = t3.elapsed();

    let (blob, syms) = tf_schema::blob_len();
    println!(
        "blob bytes: schema {blob} + symbols {syms} = {}",
        blob + syms
    );
    println!("first lookup (symbol table + 1 schema): {first:?}");
    println!("second lookup (1 schema): {second:?}");
    println!("largest schema (aws_wafv2_web_acl_rule) first lookup: {largest:?}");
    println!(
        "lookup+decode all {} schemas (cold): {all_cold:?} ({attrs} top-level attributes)",
        names.len()
    );
    println!(
        "lookup all {} schemas again (cached) + attribute(\"id\"): {all_warm:?} ({hits} have id)",
        names.len()
    );
}
