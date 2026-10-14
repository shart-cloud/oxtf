use tf_allocator::Allocator;
use tf_eval::{Evaluator, NoResolver, Scope, Value};
use tf_span::FileId;

fn ev(src: &str) -> Value {
    let alloc = Allocator::new();
    let text = alloc.alloc_str(&format!("x = {src}\n"));
    let ret = tf_parser::parse(&alloc, text);
    assert!(ret.errors.is_empty(), "{:?}", ret.errors);
    let file = alloc.alloc(ret.file);
    let attr = file.body.attributes().next().unwrap();
    let r = NoResolver;
    Evaluator::new(&r, FileId(0)).eval(&attr.value, Scope::EMPTY)
}

fn s(src: &str) -> String {
    ev(src).to_string()
}

#[test]
fn literals_and_ops() {
    assert_eq!(s("1 + 2 * 3"), "7");
    assert_eq!(s("\"a${1 + 1}b\""), "\"a2b\"");
    assert_eq!(s("true && !false"), "true");
    assert_eq!(s("[1, \"x\", null]"), "[1, \"x\", null]");
    assert_eq!(s("{ b = 1, a = \"z\" }"), "{a = \"z\", b = 1}");
    assert_eq!(s("1 == 1 ? \"y\" : \"n\""), "\"y\"");
    assert_eq!(s("[for x in [1,2,3] : x * 2 if x > 1]"), "[4, 6]");
    assert_eq!(
        s("{for k, v in {a = 1, b = 2} : v => k}"),
        "{1 = \"a\", 2 = \"b\"}"
    );
    assert_eq!(
        s("{for x in [\"a\", \"b\", \"a\"] : x => 1...}"),
        "{a = [1, 1], b = [1]}"
    );
    assert_eq!(s("[{a = 1}, {a = 2}][*].a"), "[1, 2]");
    assert_eq!(s("{a = [1, 2]}.a[1]"), "2");
}

#[test]
fn templates_strip_markers() {
    assert_eq!(s("\"a   ${~ \"b\" ~}   c\""), "\"abc\"");
    assert_eq!(
        s("<<EOT\n%{ for x in [1,2] ~}\n  ${x}\n%{~ endfor }\nEOT\n"),
        "\"12\\n\""
    );
    assert_eq!(s("\"%{ if true }yes%{ else }no%{ endif }\""), "\"yes\"");
    assert_eq!(s("\"${\"single\"}\""), "\"single\"");
}

#[test]
fn heredoc_and_json() {
    let v = ev("<<-EOF\n  {\"a\": [1]}\n  EOF\n");
    assert_eq!(v.to_string(), "\"{\\\"a\\\": [1]}\\n\"");
    assert_eq!(
        s("jsondecode(\"{\\\"a\\\": [1, true]}\")"),
        "{a = [1, true]}"
    );
    assert_eq!(
        ev("jsonencode({b = 1, a = [\"x\"]})")
            .to_str()
            .unwrap()
            .as_ref(),
        "{\"a\":[\"x\"],\"b\":1}"
    );
}

#[test]
fn functions() {
    assert_eq!(s("concat([1], [2, 3])"), "[1, 2, 3]");
    assert_eq!(s("merge({a = 1}, {b = 2}, {a = 3})"), "{a = 3, b = 2}");
    assert_eq!(s("lookup({a = 1}, \"b\", 5)"), "5");
    assert_eq!(s("format(\"%s:%d\", \"p\", 22)"), "\"p:22\"");
    assert_eq!(s("toset([\"b\", \"a\", \"b\"])"), "[\"a\", \"b\"]");
    assert_eq!(s("cidrsubnet(\"10.0.0.0/16\", 8, 1)"), "\"10.0.1.0/24\"");
    assert_eq!(s("length(flatten([[1], [2, [3]]]))"), "3");
    assert_eq!(s("coalesce(null, \"\", \"x\")"), "\"x\"");
    assert_eq!(s("try({}.missing, \"fallback\")"), "\"fallback\"");
    assert_eq!(s("can({}.missing)"), "false");
    assert_eq!(s("element([\"a\", \"b\"], 3)"), "\"b\"");
    assert_eq!(s("keys({b = 1, a = 2})"), "[\"a\", \"b\"]");
    assert_eq!(s("contains([\"a\"], \"a\")"), "true");
    assert_eq!(s("join(\",\", split(\"-\", upper(\"a-b\")))"), "\"A,B\"");
    assert_eq!(s("replace(lower(\"ABC\"), \"b\", \"x\")"), "\"axc\"");
    assert!(s("sha256(\"x\")").contains("unsupported function sha256"));
}
