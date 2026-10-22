//! Error-recovery quality: tf_parser vs hcl-edit on broken inputs.
//!
//! For each case we know which attributes are *valid* (would survive a
//! perfect recovery) and where a human would point the first error. We
//! measure: does the parser return a tree, how many valid attributes it
//! recovers (present with an error-free value), and the line distance between
//! its first error and the ideal position. Run with `--nocapture` for the
//! table used in docs/findings/W1.md.

use tf_ast::{AstKind, Visit};
use tf_span::LineIndex;

struct Case {
    name: &'static str,
    src: &'static str,
    /// Attribute keys a perfect recovery keeps.
    valid: &'static [&'static str],
    /// 1-based (line, col) of the ideal first error.
    ideal: (u32, u32),
}

const CASES: &[Case] = &[
    Case {
        name: "missing `}` (block)",
        src: "resource \"a\" \"b\" {\n  x = 1\n\nresource \"c\" \"d\" {\n  y = 2\n}\nz = 3\n",
        valid: &["x", "y", "z"],
        ideal: (1, 18),
    },
    Case {
        name: "unterminated string",
        src: "a = \"abc\nb = 2\nc = 3\n",
        valid: &["b", "c"],
        ideal: (1, 5),
    },
    Case {
        name: "stray tokens line",
        src: "a = 1\n) ] ;\nb = 2\n",
        valid: &["a", "b"],
        ideal: (2, 1),
    },
    Case {
        name: "missing `=`",
        src: "a 1\nb = 2\nc = 3\n",
        valid: &["b", "c"],
        ideal: (1, 3),
    },
    Case {
        name: "missing `]`",
        src: "a = [1, 2\nb = 3\nc = 4\n",
        valid: &["b", "c"],
        ideal: (1, 5),
    },
    Case {
        name: "missing `)`",
        src: "a = f(1, 2\nb = 3\nc = 4\n",
        valid: &["b", "c"],
        ideal: (1, 6),
    },
    Case {
        name: "dangling operator",
        src: "a = 1 +\nb = 2\nc = 3\n",
        valid: &["b", "c"],
        ideal: (1, 8),
    },
    Case {
        name: "unclosed `${`",
        src: "a = \"x ${var.y\"\nb = 2\nc = 3\n",
        valid: &["b", "c"],
        ideal: (1, 15),
    },
    Case {
        name: "object item missing `=`",
        src: "a = {\n  k v\n  ok = 1\n}\nb = 2\n",
        valid: &["ok", "b"],
        ideal: (2, 5),
    },
    Case {
        name: "error inside nested block",
        src: "resource \"r\" \"n\" {\n  a = 1\n  b = = 2\n  nested {\n    c = 3\n  }\n}\nd = 4\n",
        valid: &["a", "c", "d"],
        ideal: (3, 7),
    },
    Case {
        name: "unterminated heredoc",
        src: "a = 1\nb = <<EOT\nhello\nc = 2\n",
        valid: &["a"],
        ideal: (2, 5),
    },
    Case {
        name: "two attributes on one line",
        src: "a = 1 b = 2\nc = 3\n",
        valid: &["c"],
        ideal: (1, 7),
    },
];

/// Collects attribute and object-item keys whose value contains no
/// `ErrorExpr`.
#[derive(Default)]
struct Keys<'a> {
    names: Vec<&'a str>,
}

struct HasError(bool);
impl<'a> Visit<'a> for HasError {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        if matches!(kind, AstKind::ErrorExpr(_)) {
            self.0 = true;
        }
    }
}

impl<'a> Visit<'a> for Keys<'a> {
    fn visit_attribute(&mut self, it: &'a tf_ast::Attribute<'a>) {
        let mut h = HasError(false);
        h.visit_expression(&it.value);
        if !h.0 {
            self.names.push(it.key.name.as_str());
        }
        tf_ast::visit::walk_attribute(self, it);
    }
    fn visit_object_item(&mut self, it: &'a tf_ast::ObjectItem<'a>) {
        let mut h = HasError(false);
        h.visit_expression(&it.value);
        if let (false, Some(k)) = (h.0, it.key.as_static_str()) {
            self.names.push(k);
        }
        tf_ast::visit::walk_object_item(self, it);
    }
}

fn hcl_edit_keys(body: &hcl_edit::structure::Body, out: &mut Vec<String>) {
    for s in body.iter() {
        match s {
            hcl_edit::structure::Structure::Attribute(a) => {
                out.push(a.key.as_str().to_string());
                if let hcl_edit::expr::Expression::Object(o) = &a.value {
                    for (k, _) in o.iter() {
                        if let hcl_edit::expr::ObjectKey::Ident(i) = k {
                            out.push(i.as_str().to_string());
                        }
                    }
                }
            }
            hcl_edit::structure::Structure::Block(b) => hcl_edit_keys(&b.body, out),
        }
    }
}

#[test]
fn recovery_quality_table() {
    println!(
        "| case | tf_parser tree | tf_parser recovered | tf_parser errors | tf_parser 1st error (ideal) | hcl-edit tree | hcl-edit recovered | hcl-edit error (ideal) |"
    );
    println!("|---|---|---|---|---|---|---|---|");
    let mut total_valid = 0;
    let mut total_mine = 0;
    let mut total_theirs = 0;
    let mut mine_exact = 0;
    let mut theirs_exact = 0;
    for case in CASES {
        let alloc = tf_allocator::Allocator::new();
        let ret = tf_parser::parse(&alloc, case.src);
        let file = alloc.alloc(ret.file).unwrap();
        let mut keys = Keys::default();
        keys.visit_file(file);
        let recovered = case.valid.iter().filter(|v| keys.names.contains(v)).count();
        let idx = LineIndex::new(case.src);
        let first = ret.errors.first().map(|e| idx.line_col(e.span.start));
        assert!(first.is_some(), "{}: expected an error", case.name);
        if first == Some(case.ideal) {
            mine_exact += 1;
        }

        let (h_tree, h_rec, h_pos) = match hcl_edit::parser::parse_body(case.src) {
            Ok(body) => {
                let mut names = Vec::new();
                hcl_edit_keys(&body, &mut names);
                let rec = case
                    .valid
                    .iter()
                    .filter(|v| names.iter().any(|n| n == *v))
                    .count();
                (true, rec, None)
            }
            Err(e) => {
                let loc = e.location();
                (false, 0, Some((loc.line() as u32, loc.column() as u32)))
            }
        };
        if h_pos == Some(case.ideal) {
            theirs_exact += 1;
        }
        total_valid += case.valid.len();
        total_mine += recovered;
        total_theirs += h_rec;
        let fmt = |p: Option<(u32, u32)>| p.map_or("-".to_string(), |(l, c)| format!("{l}:{c}"));
        println!(
            "| {} | yes | {}/{} | {} | {} ({}) | {} | {}/{} | {} ({}) |",
            case.name,
            recovered,
            case.valid.len(),
            ret.errors.len(),
            fmt(first),
            fmt(Some(case.ideal)),
            if h_tree { "yes" } else { "no" },
            h_rec,
            case.valid.len(),
            fmt(h_pos),
            fmt(Some(case.ideal)),
        );
    }
    println!(
        "| **total** | {n}/{n} | {total_mine}/{total_valid} | | {mine_exact}/{n} exact | | {total_theirs}/{total_valid} | {theirs_exact}/{n} exact |",
        n = CASES.len()
    );
    // Regression guard: recover at least 90% of valid attributes.
    assert!(
        total_mine * 10 >= total_valid * 9,
        "recovered {total_mine}/{total_valid}"
    );
}

/// Regression from the final code review: recovering from a templated,
/// unterminated block label that ends in a multi-byte character must not
/// slice inside the character.
#[test]
fn unterminated_template_label_with_multibyte_char_does_not_panic() {
    let alloc = tf_allocator::Allocator::new();
    let ret = tf_parser::parse(&alloc, "resource \"a${b}é\n");
    assert!(!ret.errors.is_empty());
}
