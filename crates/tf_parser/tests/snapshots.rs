//! insta snapshot tests for tricky inputs, plus a differential check of each
//! valid case against `hcl-edit`.

mod common;

use tf_parser::dump::{Options, dump_file};

/// (name, source). Cases whose name starts with `err_` are expected to
/// produce diagnostics.
const CASES: &[(&str, &str)] = &[
    (
        "template_directives",
        r#"a = "%{ if var.enabled }on%{ else }off%{ endif }"
b = "%{ for i, v in var.list ~} ${i}=${v}, %{~ endfor }"
c = "pre ${~ var.x ~} post"
d = "%{ if a }%{ for x in b }${x}%{ endfor }%{ endif }"
"#,
    ),
    (
        "heredocs",
        "plain = <<EOT\nline one\n  ${var.x}\nEOT\nindented = <<-EOT\n    first\n      second ${var.y}\n\n    third\n    EOT\njson = jsonencode(<<EOF\n{\"a\": 1}\nEOF\n)\nempty = <<EOT\nEOT\n",
    ),
    (
        // Known hcl-edit divergence, see KNOWN_HCL_EDIT_DIVERGENCES.
        "heredoc_indented_directive",
        "with_directive = <<-EOT\n  %{ for s in var.subnets ~}\n  subnet ${s}\n  %{ endfor ~}\n  EOT\n",
    ),
    (
        "nested_for",
        r#"a = [for outer in var.x : [for inner in outer : inner.id if inner != null]]
b = {for k, v in var.m : k => [for i in v : i * 2]...}
c = {
  for k, v in var.m :
  k => v
  if v != ""
}
d = [for i, s in var.l : "${i}-${s}"]
"#,
    ),
    (
        "splats_and_traversals",
        r#"a = aws_instance.web.*.id
b = aws_instance.web[*].private_ip
c = module.vpc.private_subnets[0]
d = var.list.0.name
e = aws_instance.x[*].tags["Name"]
f = data.aws_iam_policy_document.p.json
g = local.m[var.k].attr[*]
h = foo().bar[0]
i = [1, 2][0]
j = var.a.0.1
"#,
    ),
    (
        "objects",
        r#"tags = {
  Name = "x"
  "quoted" = 1
  colon: 2
  (var.k) = 3
  a = 1, b = 2
  nested = { x = { y = true } }
  multi = (
    1 +
    2
  )
}
providers = {
  aws.east = aws.east
}
empty = {}
oneline = { a = 1, b = 2 }
"#,
    ),
    (
        "comments",
        r#"# hash comment
// slash comment
/* block
   comment */
a = 1 # trailing hash
b = [
  1, // inside list
  /* inline */ 2,
]
c = {
  k = "v" # inside object
}
"#,
    ),
    (
        "operators",
        r#"a = 1 + 2 * 3 - 4 / 5 % 6
b = !var.x && var.y || var.z == 1 && var.w != 2
c = var.a < 1 || var.b >= 2 && var.c <= 3 || var.d > 4
d = var.x ? var.y ? 1 : 2 : var.z ? 3 : 4
e = -var.n + -1
f = !!true
g = (1 + 2) * 3
h = var.a == null ? "default" : var.a
"#,
    ),
    (
        "function_calls",
        r#"a = merge(var.a, var.b, {})
b = concat(var.lists...)
c = provider::aws::arn_parse(var.arn).account_id
d = format(
  "%s-%s",
  var.a,
  var.b,
)
e = lookup(var.m, "k", null)
f = cidrsubnet(var.cidr, 8, count.index)
g = timestamp()
"#,
    ),
    (
        "unknown_blocks",
        r#"moved {
  from = aws_instance.a
  to   = aws_instance.b
}
import {
  to = aws_s3_bucket.b
  id = "bucket"
}
removed {
  from = aws_instance.c
  lifecycle { destroy = false }
}
check "health" {
  data "http" "h" { url = "https://example.com" }
  assert {
    condition     = data.http.h.status_code == 200
    error_message = "down"
  }
}
anything ident_label "string_label" {}
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}
"#,
    ),
    (
        "string_escapes",
        r#"a = "quote \" backslash \\ newline \n tab \t unicode é \U0001F600"
b = "literal $${not_interp} and %%{not_directive}"
c = ""
d = "$ and % alone, ${"nested ${"deep"}"}"
"#,
    ),
    (
        "newlines_in_brackets",
        "a = [\n  1,\n  2,\n]\nb = (\n  1 +\n  2\n)\nc = f(\n)\nd = [\n]\ne = var.x ? [\n  1\n] : []\nf = {\n\n  a = 1\n\n}\n",
    ),
    (
        "tfvars",
        "region = \"us-east-1\"\ncidrs  = [\"10.0.0.0/16\"]\ntags   = { env = \"prod\" }\ncount  = 3\nratio  = 1.5e3\n",
    ),
    (
        "crlf",
        "a = 1\r\nb = \"x\"\r\nc {\r\n  d = <<EOT\r\nhi\r\nEOT\r\n}\r\n",
    ),
    // ---- error recovery ----
    (
        "err_missing_rbrace",
        "resource \"a\" \"b\" {\n  x = 1\n\nresource \"c\" \"d\" {\n  y = 2\n}\n",
    ),
    ("err_unterminated_string", "a = \"abc\nb = 2\nc = 3\n"),
    ("err_stray_token", "a = 1\n) ] ;\nb = 2\n"),
    ("err_missing_eq", "a 1\nb = 2\n"),
    ("err_missing_rbracket", "a = [1, 2\nb = 3\n"),
    ("err_missing_rparen", "a = f(1, 2\nb = 3\n"),
    ("err_bad_expression", "a = 1 +\nb = * 2\nc = 3\n"),
    ("err_unclosed_interp", "a = \"x ${var.y\"\nb = 2\n"),
    ("err_missing_endif", "a = \"%{ if x }yes\"\nb = 2\n"),
    ("err_unexpected_rbrace", "}\na = 1\n"),
    (
        "err_object_missing_eq",
        "a = {\n  k v\n  ok = 1\n}\nb = 2\n",
    ),
    ("err_unterminated_heredoc", "a = <<EOT\nhello\nb = 2\n"),
];

fn render(src: &str) -> String {
    let alloc = tf_allocator::Allocator::new();
    let ret = tf_parser::parse(&alloc, src);
    let mut out = dump_file(&ret.file, Options::default());
    out.push_str("\n--- comments\n");
    for c in &ret.comments {
        out.push_str(&format!("{:?} {:?}\n", c.kind, c.span.source_text(src)));
    }
    out.push_str("--- errors\n");
    let idx = tf_span::LineIndex::new(src);
    for e in &ret.errors {
        let (l, c) = idx.line_col(e.span.start);
        out.push_str(&format!("{l}:{c} {}\n", e.message));
    }
    out
}

#[test]
fn snapshots() {
    for (name, src) in CASES {
        let rendered = render(src);
        insta::with_settings!({ description => *src, omit_expression => true }, {
            insta::assert_snapshot!(*name, rendered);
        });
    }
}

/// Spans on one representative case.
#[test]
fn snapshot_spans() {
    let src = "resource \"x\" \"y\" {\n  a = var.b[0].c\n  t = \"p${q}\"\n}\n";
    let alloc = tf_allocator::Allocator::new();
    let ret = tf_parser::parse(&alloc, src);
    insta::assert_snapshot!(dump_file(
        &ret.file,
        Options {
            spans: true,
            ..Options::default()
        }
    ));
}

/// Cases where tf_parser intentionally differs from hcl-edit 0.9.7.
///
/// `heredoc_indented_directive`: for `<<-` heredocs hcl-edit only dedents
/// literals at the top level of the template (`Template::dedent`), leaving
/// literals inside `%{ for }` / `%{ if }` bodies indented. HCL's Go
/// implementation (`flushHeredocTemplateParts`) strips the common indent from
/// the flat token list, i.e. including literals inside directives; tf_parser
/// follows Go. Not observed in the corpus.
const KNOWN_HCL_EDIT_DIVERGENCES: &[&str] = &["heredoc_indented_directive"];

#[test]
fn valid_cases_parse_cleanly_and_match_hcl_edit() {
    let opts = Options {
        spans: false,
        normalize: true,
        dedupe_object_keys: true,
    };
    for (name, src) in CASES {
        if name.starts_with("err_") {
            continue;
        }
        let alloc = tf_allocator::Allocator::new();
        let ret = tf_parser::parse(&alloc, src);
        assert!(ret.errors.is_empty(), "{name}: {:?}", ret.errors);
        let mine = dump_file(&ret.file, opts);
        let body = hcl_edit::parser::parse_body(src)
            .unwrap_or_else(|e| panic!("hcl-edit rejected {name}: {e}"));
        let theirs = common::hcl_body(&body);
        if KNOWN_HCL_EDIT_DIVERGENCES.contains(name) {
            assert_ne!(
                mine, theirs,
                "{name}: known divergence no longer diverges; update the list"
            );
            continue;
        }
        assert_eq!(mine, theirs, "{name} diverges from hcl-edit");
    }
}

#[test]
fn error_cases_report_errors() {
    for (name, src) in CASES {
        if !name.starts_with("err_") {
            continue;
        }
        let alloc = tf_allocator::Allocator::new();
        let ret = tf_parser::parse(&alloc, src);
        assert!(!ret.errors.is_empty(), "{name} should report an error");
    }
}
