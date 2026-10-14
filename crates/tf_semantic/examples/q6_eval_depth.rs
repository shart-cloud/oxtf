//! Q6 (evaluator depth): which expression forms and functions appear in
//! security-relevant attributes across the corpus, and how often the
//! evaluator gets a Known value for them.
//!
//! cargo run -p tf_semantic --release --example q6_eval_depth -- corpus/repos
//!
//! Module roots: every directory under the given path that contains `.tf`
//! files. Each root is analysed on its own (its root variables bound from
//! defaults / tfvars; local child modules followed). A module directory is
//! therefore evaluated once as a root and once more for every local caller.
//! Expression *forms* are counted once per source location (deduplicated
//! across contexts); evaluation *results* are counted per evaluation context.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use tf_ast::{Expression, GetSpan, TemplateElement, TraversalOperator};
use tf_eval::{Kind, Known, Value};
use tf_semantic::{AnalyzeOptions, FileTable, ObservedAttr, analyze_module_observed};

/// Attribute names treated as security-relevant: every attribute the five
/// seed rules read, plus common network / encryption / exposure / IAM
/// settings.
const SECURITY_ATTRS: &[&str] = &[
    // seed rules
    "cidr_blocks",
    "ipv6_cidr_blocks",
    "cidr_ipv4",
    "cidr_ipv6",
    "from_port",
    "to_port",
    "protocol",
    "ip_protocol",
    "policy",
    "storage_encrypted",
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
    "uniform_bucket_level_access",
    "bucket",
    // network exposure
    "source_ranges",
    "source_security_group_id",
    "prefix_list_ids",
    "map_public_ip_on_launch",
    "associate_public_ip_address",
    "publicly_accessible",
    "internal",
    "ingress",
    "egress",
    "authorized_networks",
    "master_authorized_networks_config",
    "enable_private_nodes",
    "enable_private_endpoint",
    "public_network_access_enabled",
    "endpoint_public_access",
    "public_access_cidrs",
    "allowed_ip_ranges",
    // encryption
    "encrypted",
    "kms_key_id",
    "kms_master_key_id",
    "kms_key_arn",
    "sse_algorithm",
    "enable_key_rotation",
    "encryption_configuration",
    "default_kms_key_name",
    "kms_key_name",
    "server_side_encryption",
    "at_rest_encryption_enabled",
    "transit_encryption_enabled",
    "min_tls_version",
    "ssl_policy",
    "https_only",
    "enforce_ssl",
    // access / identity
    "assume_role_policy",
    "acl",
    "public_access_prevention",
    "iam_database_authentication_enabled",
    "deletion_protection",
    "http_tokens",
    "http_endpoint",
    "versioning",
    "logging",
    "role_entity",
    "members",
    "member",
    "role",
    "principals",
    "actions",
    "resources",
    "effect",
    "allow_blob_public_access",
    "shared_access_key_enabled",
];

fn is_security(name: &str) -> bool {
    SECURITY_ATTRS.contains(&name)
        || name.ends_with("_encrypted")
        || name.starts_with("block_public_")
}

fn top_form(e: &Expression<'_>, lexical: &HashSet<&str>) -> String {
    match e.without_parens() {
        Expression::Null(_)
        | Expression::Bool(_)
        | Expression::Number(_)
        | Expression::String(_) => "literal".into(),
        Expression::Tuple(_) | Expression::Object(_) => {
            if is_literal(e) {
                "literal collection".into()
            } else {
                "tuple/object with references".into()
            }
        }
        Expression::Template(_) => "template".into(),
        Expression::Heredoc(_) => "heredoc".into(),
        Expression::Variable(v) => ref_form(&v.name, &[], lexical),
        Expression::Traversal(t) => match &t.object {
            Expression::Variable(v) => {
                let f = ref_form(&v.name, &t.operators, lexical);
                if t.operators.iter().any(|o| {
                    matches!(
                        o,
                        TraversalOperator::FullSplat(_) | TraversalOperator::AttrSplat(_)
                    )
                }) {
                    format!("{f} + splat")
                } else {
                    f
                }
            }
            _ => "traversal of expression".into(),
        },
        Expression::FunctionCall(f) => format!("call {}", f.full_name()),
        Expression::For(_) => "for".into(),
        Expression::Conditional(_) => "conditional".into(),
        Expression::Unary(_) | Expression::Binary(_) => "operator".into(),
        Expression::Parenthesized(_) => unreachable!(),
        Expression::Error(_) => "error".into(),
    }
}

fn ref_form(root: &str, ops: &[TraversalOperator<'_>], lexical: &HashSet<&str>) -> String {
    match root {
        "var" => "var ref".into(),
        "local" => "local ref".into(),
        "module" => "module output ref".into(),
        "data" => "data source ref".into(),
        "each" | "count" | "self" => format!("{root} ref"),
        "path" | "terraform" => format!("{root} ref"),
        r if lexical.contains(r) => "iterator / for variable ref".into(),
        _ if ops.is_empty() => "bare name".into(),
        _ => "resource ref".into(),
    }
}

fn is_literal(e: &Expression<'_>) -> bool {
    match e.without_parens() {
        Expression::Null(_)
        | Expression::Bool(_)
        | Expression::Number(_)
        | Expression::String(_) => true,
        Expression::Tuple(t) => t.elements.iter().all(is_literal),
        Expression::Object(o) => o.items.iter().all(|i| is_literal(&i.value)),
        _ => false,
    }
}

/// Every form / function name occurring anywhere in the expression.
fn nested(e: &Expression<'_>, out: &mut HashSet<String>, funcs: &mut HashSet<String>) {
    match e {
        Expression::Template(t) => {
            out.insert("template".into());
            tmpl(&t.template, out, funcs)
        }
        Expression::Heredoc(h) => {
            out.insert("heredoc".into());
            tmpl(&h.template, out, funcs)
        }
        Expression::Variable(v) => {
            out.insert(ref_form(&v.name, &[], &HashSet::new()));
        }
        Expression::Traversal(t) => {
            if let Expression::Variable(v) = &t.object {
                out.insert(ref_form(&v.name, &t.operators, &HashSet::new()));
            } else {
                nested(&t.object, out, funcs);
            }
            for o in t.operators.iter() {
                match o {
                    TraversalOperator::Index(ix) => {
                        out.insert("index".into());
                        nested(&ix.index, out, funcs)
                    }
                    TraversalOperator::FullSplat(_) | TraversalOperator::AttrSplat(_) => {
                        out.insert("splat".into());
                    }
                    _ => {}
                }
            }
        }
        Expression::FunctionCall(f) => {
            funcs.insert(f.full_name());
            out.insert("function call".into());
            f.arguments.iter().for_each(|a| nested(a, out, funcs));
        }
        Expression::Tuple(t) => t.elements.iter().for_each(|a| nested(a, out, funcs)),
        Expression::Object(o) => o.items.iter().for_each(|i| nested(&i.value, out, funcs)),
        Expression::For(f) => {
            out.insert("for".into());
            nested(&f.collection, out, funcs);
            nested(&f.value_expr, out, funcs);
            if let Some(k) = &f.key_expr {
                nested(k, out, funcs)
            }
            if let Some(c) = &f.condition {
                nested(c, out, funcs)
            }
        }
        Expression::Conditional(c) => {
            out.insert("conditional".into());
            nested(&c.condition, out, funcs);
            nested(&c.true_expr, out, funcs);
            nested(&c.false_expr, out, funcs)
        }
        Expression::Unary(u) => {
            out.insert("operator".into());
            nested(&u.operand, out, funcs)
        }
        Expression::Binary(b) => {
            out.insert("operator".into());
            nested(&b.left, out, funcs);
            nested(&b.right, out, funcs)
        }
        Expression::Parenthesized(p) => nested(&p.expression, out, funcs),
        _ => {}
    }
}

fn tmpl(t: &tf_ast::Template<'_>, out: &mut HashSet<String>, funcs: &mut HashSet<String>) {
    for el in t.elements.iter() {
        match el {
            TemplateElement::Interpolation(i) => nested(&i.expression, out, funcs),
            TemplateElement::If(i) => {
                out.insert("template directive".into());
                nested(&i.condition, out, funcs)
            }
            TemplateElement::For(f) => {
                out.insert("template directive".into());
                nested(&f.collection, out, funcs)
            }
            _ => {}
        }
    }
}

/// Result class and, when not wholly known, the first non-known origin.
fn classify(v: &Value) -> (&'static str, Option<String>) {
    match &v.kind {
        Kind::Known(_) if v.is_wholly_known() => ("known", None),
        Kind::Known(_) => ("partially known", first_non_known(v)),
        Kind::Unknown(o) => ("unknown", Some(o.category())),
        Kind::Tainted(_) => ("tainted (unconstrained variable)", Some("tainted".into())),
        Kind::OneOf(_) => ("one-of", None),
    }
}

fn first_non_known(v: &Value) -> Option<String> {
    match &v.kind {
        Kind::Known(Known::List(l)) => l.iter().find_map(first_non_known),
        Kind::Known(Known::Object(m)) => m.values().find_map(first_non_known),
        Kind::Known(Known::Json(j)) => first_non_known(j),
        Kind::Known(_) => None,
        Kind::Unknown(o) => Some(o.category()),
        Kind::Tainted(_) => Some("tainted".into()),
        Kind::OneOf(_) => Some("one-of".into()),
    }
}

fn roots(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    entries.sort();
    if entries
        .iter()
        .any(|p| p.is_file() && p.extension().is_some_and(|x| x == "tf"))
    {
        out.push(dir.to_path_buf());
    }
    for p in entries {
        if p.is_dir()
            && !p
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with('.'))
        {
            roots(&p, out);
        }
    }
}

fn print_table(title: &str, m: &BTreeMap<String, usize>, total: usize, limit: usize) {
    println!("\n### {title}\n");
    println!("| form | count | share |");
    println!("|---|---:|---:|");
    let mut v: Vec<(&String, &usize)> = m.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (k, c) in v.into_iter().take(limit) {
        println!(
            "| {k} | {c} | {:.1}% |",
            100.0 * *c as f64 / total.max(1) as f64
        );
    }
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "corpus/repos".into());
    let mut rs = Vec::new();
    roots(Path::new(&dir), &mut rs);
    let files = FileTable::new();
    let opts = AnalyzeOptions::default();

    let mut seen: HashSet<(u32, u32, u32)> = HashSet::new();
    let mut top: BTreeMap<String, usize> = BTreeMap::new();
    let mut anywhere: BTreeMap<String, usize> = BTreeMap::new();
    let mut funcs: BTreeMap<String, usize> = BTreeMap::new();
    let mut results: BTreeMap<String, usize> = BTreeMap::new();
    let mut origins: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_attr: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut known_somewhere: HashMap<(u32, u32, u32), bool> = HashMap::new();
    let mut n_locations = 0usize;
    let mut n_evals = 0usize;
    let debug = std::env::var("Q6_DEBUG").ok();
    let mut debug_left = 12;
    let start = std::time::Instant::now();
    for r in &rs {
        let mut obs = |o: &ObservedAttr<'_, '_>| {
            if !is_security(o.name) {
                return;
            }
            let sp = o.expr.span();
            let key = (o.file.0, sp.start, sp.end);
            let (class, origin) = classify(o.value);
            n_evals += 1;
            *results.entry(class.into()).or_default() += 1;
            if let Some(org) = origin {
                if let Some(d) = &debug
                    && org.contains(d.as_str())
                    && debug_left > 0
                {
                    debug_left -= 1;
                    let f = files.get(o.file);
                    let sp = o.expr.span();
                    eprintln!(
                        "[{}] {}:{} {} = {} -> {}",
                        r.display(),
                        f.path.display(),
                        f.line(sp.start),
                        o.path,
                        sp.source_text(&f.text),
                        o.value
                    );
                }
                *origins.entry(org).or_default() += 1;
            }
            let e = by_attr.entry(o.name.to_string()).or_default();
            e.0 += 1;
            if class == "known" {
                e.1 += 1;
            }
            *known_somewhere.entry(key).or_default() |= class == "known";
            if !seen.insert(key) {
                return;
            }
            n_locations += 1;
            let lexical: HashSet<&str> = HashSet::new();
            *top.entry(top_form(o.expr, &lexical)).or_default() += 1;
            let mut forms = HashSet::new();
            let mut fs = HashSet::new();
            nested(o.expr, &mut forms, &mut fs);
            if forms.is_empty() {
                forms.insert("literal only".into());
            }
            for f in forms {
                *anywhere.entry(f).or_default() += 1;
            }
            for f in fs {
                *funcs.entry(f).or_default() += 1;
            }
        };
        let _ = analyze_module_observed(r, &opts, &files, Some(&mut obs));
    }
    let elapsed = start.elapsed();
    let known_locs = known_somewhere.values().filter(|k| **k).count();
    println!(
        "module roots: {}  files loaded: {}  elapsed: {:.2?}",
        rs.len(),
        files.len(),
        elapsed
    );
    println!(
        "security-relevant attribute locations: {n_locations}; evaluations (all contexts): {n_evals}"
    );
    println!(
        "locations Known in at least one context: {known_locs} ({:.1}%)",
        100.0 * known_locs as f64 / n_locations.max(1) as f64
    );
    print_table(
        "Top-level expression form (per source location)",
        &top,
        n_locations,
        40,
    );
    print_table(
        "Forms occurring anywhere in the expression (per source location; an expression counts once per form)",
        &anywhere,
        n_locations,
        40,
    );
    print_table(
        "Functions called anywhere in security-relevant expressions (per source location)",
        &funcs,
        n_locations,
        60,
    );
    print_table("Evaluation result (per evaluation)", &results, n_evals, 10);
    print_table(
        "First non-known origin, for unknown / partially known / tainted / one-of results (per evaluation)",
        &origins,
        n_evals,
        30,
    );
    println!("\n### Per attribute: evaluations, Known (wholly)\n");
    println!("| attribute | evaluations | known | share |");
    println!("|---|---:|---:|---:|");
    let mut v: Vec<_> = by_attr.into_iter().collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.1.0));
    for (k, (n, kn)) in v.into_iter().take(40) {
        println!(
            "| {k} | {n} | {kn} | {:.1}% |",
            100.0 * kn as f64 / n.max(1) as f64
        );
    }
    // Every function call site in the corpus (all attributes, not only
    // security-relevant ones), for ranking evaluator work.
    let mut all_calls: BTreeMap<String, usize> = BTreeMap::new();
    let mut n_calls = 0usize;
    for sf in files.all() {
        let alloc = tf_allocator::Allocator::new();
        let text = alloc.alloc_str(&sf.text);
        let ret = tf_parser::parse(&alloc, text);
        // (body, is a `variable` block): its `type` constraint is not a
        // function call (`object(...)`, `optional(...)`, `list(...)`).
        let mut stack: Vec<(&tf_ast::Body<'_>, bool)> = vec![(&ret.file.body, false)];
        while let Some((b, is_var)) = stack.pop() {
            for a in b.attributes() {
                if is_var && a.key.name.as_str() == "type" {
                    continue;
                }
                count_calls(&a.value, &mut all_calls, &mut n_calls);
            }
            for blk in b.blocks() {
                stack.push((&blk.body, blk.block_type() == "variable"));
            }
        }
    }
    println!(
        "\n### All function call sites in the corpus, excluding variable type constraints ({n_calls} calls in {} files)\n",
        files.len()
    );
    println!("| function | calls | share | implemented |");
    println!("|---|---:|---:|---|");
    let mut v: Vec<_> = all_calls.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let mut covered = 0usize;
    for (k, c) in &v {
        if tf_eval::functions::is_supported(k) {
            covered += **c;
        }
    }
    for (k, c) in v.iter().take(60) {
        println!(
            "| {k} | {c} | {:.1}% | {} |",
            100.0 * **c as f64 / n_calls.max(1) as f64,
            if tf_eval::functions::is_supported(k) {
                "yes"
            } else {
                "**no**"
            }
        );
    }
    println!(
        "\ndistinct functions: {}; call sites covered by implemented functions: {covered}/{n_calls} ({:.1}%)",
        v.len(),
        100.0 * covered as f64 / n_calls.max(1) as f64
    );
    let missing: Vec<String> = v
        .iter()
        .filter(|(k, _)| !tf_eval::functions::is_supported(k))
        .map(|(k, c)| format!("{k} ({c})"))
        .collect();
    println!("not implemented, by frequency: {}", missing.join(", "));
    let unsupported: Vec<String> = funcs
        .keys()
        .filter(|f| !tf_eval::functions::is_supported(f))
        .cloned()
        .collect();
    println!("\nfunctions seen but not implemented: {unsupported:?}");
}

fn count_calls(e: &Expression<'_>, out: &mut BTreeMap<String, usize>, n: &mut usize) {
    let mut forms = HashSet::new();
    let mut fs = HashSet::new();
    // reuse the nested walker, but count every call site: walk manually
    match e {
        Expression::FunctionCall(f) => {
            *out.entry(f.full_name()).or_default() += 1;
            *n += 1;
            f.arguments.iter().for_each(|a| count_calls(a, out, n));
        }
        Expression::Template(t) => tmpl_calls(&t.template, out, n),
        Expression::Heredoc(h) => tmpl_calls(&h.template, out, n),
        Expression::Traversal(t) => {
            count_calls(&t.object, out, n);
            for o in t.operators.iter() {
                if let TraversalOperator::Index(ix) = o {
                    count_calls(&ix.index, out, n);
                }
            }
        }
        Expression::Tuple(t) => t.elements.iter().for_each(|a| count_calls(a, out, n)),
        Expression::Object(o) => o.items.iter().for_each(|i| count_calls(&i.value, out, n)),
        Expression::For(f) => {
            count_calls(&f.collection, out, n);
            count_calls(&f.value_expr, out, n);
            if let Some(k) = &f.key_expr {
                count_calls(k, out, n)
            }
            if let Some(c) = &f.condition {
                count_calls(c, out, n)
            }
        }
        Expression::Conditional(c) => {
            count_calls(&c.condition, out, n);
            count_calls(&c.true_expr, out, n);
            count_calls(&c.false_expr, out, n)
        }
        Expression::Unary(u) => count_calls(&u.operand, out, n),
        Expression::Binary(b) => {
            count_calls(&b.left, out, n);
            count_calls(&b.right, out, n)
        }
        Expression::Parenthesized(p) => count_calls(&p.expression, out, n),
        _ => nested(e, &mut forms, &mut fs),
    }
}

fn tmpl_calls(t: &tf_ast::Template<'_>, out: &mut BTreeMap<String, usize>, n: &mut usize) {
    for el in t.elements.iter() {
        match el {
            TemplateElement::Interpolation(i) => count_calls(&i.expression, out, n),
            TemplateElement::If(i) => {
                count_calls(&i.condition, out, n);
                tmpl_calls(&i.then_template, out, n);
                if let Some(e) = &i.else_template {
                    tmpl_calls(e, out, n)
                }
            }
            TemplateElement::For(f) => {
                count_calls(&f.collection, out, n);
                tmpl_calls(&f.template, out, n)
            }
            _ => {}
        }
    }
}
