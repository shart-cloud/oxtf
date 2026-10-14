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

// Regressions from the final code review.

#[test]
fn attr_splat_carries_only_attribute_accesses() {
    // `.*` applies only the following `.attr`s per element; `[0]` indexes the result.
    assert_eq!(s("[{a = [1, 2]}, {a = [3, 4]}].*.a[0]"), "[1, 2]");
    // `[*]` carries every following operator.
    assert_eq!(s("[{a = [1, 2]}, {a = [3, 4]}][*].a[0]"), "[1, 3]");
}

#[test]
fn parseint_rejects_bad_base_without_panicking() {
    assert!(ev("parseint(\"10\", 1)").is_error());
    assert!(ev("parseint(\"10\", 0)").is_error());
    assert!(ev("parseint(\"10\", 37)").is_error());
    assert_eq!(s("parseint(\"ff\", 16)"), "255");
}

#[test]
fn split_empty_string_is_one_empty_element() {
    assert_eq!(s("split(\",\", \"\")"), "[\"\"]");
    assert_eq!(s("length(split(\",\", \"\"))"), "1");
}

#[test]
fn cidr_functions_follow_terraform() {
    // Allocation starts at the network address, not the host address.
    assert_eq!(s("cidrsubnets(\"10.1.2.3/16\", 8)"), "[\"10.1.0.0/24\"]");
    // Running out of space inside the prefix is an error, not a subnet outside it.
    assert!(ev("cidrsubnets(\"10.0.0.0/24\", 1, 1, 1)").is_error());
    assert_eq!(
        s("cidrsubnets(\"10.0.0.0/24\", 1, 1)"),
        "[\"10.0.0.0/25\", \"10.0.0.128/25\"]"
    );
    // A huge negative host number is out of range, not an overflow panic.
    assert!(ev("cidrhost(\"10.0.0.0/8\", -1e40)").is_error());
    assert_eq!(s("cidrhost(\"10.0.0.0/8\", -1)"), "\"10.255.255.255\"");
}
