package oxtf.iam
import rego.v1
import data.oxtf.lattice as l

matches(v, op) if {
    op == "wildcard"
    v.text == "*"
}
matches(v, op) if {
    op == "allow"
    v.string == "Allow"
}
scalar(v, op) := {"rank":3,"evidence":v.handle} if {
    v.kind == "known"
    matches(v, op)
}
scalar(v, op) := {"rank":0,"evidence":v.handle} if {
    v.kind == "known"
    not matches(v, op)
}
scalar(v, op) := {"rank":1,"evidence":v.handle} if v.kind == "unknown"
scalar(v, op) := {"rank":2,"evidence":v.handle} if v.kind == "tainted"
atom(v, op) := scalar(v, op) if v.kind != "one_of"
atom(v, op) := result if {
    v.kind == "one_of"
    vs := [scalar(a, op) | a := v.alternatives[_]]
    result := l.choice(vs, v.tainted)
}

wild_base(v) := scalar(v, "wildcard") if v.kind != "known"
wild_base(v) := l.false_result if {
    v.kind == "known"
    v.type == "null"
}
wild_base(v) := result if {
    v.kind == "known"
    v.type == "list"
    vs := [atom(a, "wildcard") | a := v.elements[_]]
    result := l.any(vs)
}
wild_base(v) := atom(v.single, "wildcard") if {
    v.kind == "known"
    not v.type in {"list", "null"}
}
wild(v) := wild_base(v) if v.kind != "one_of"
wild(v) := result if {
    v.kind == "one_of"
    vs := [wild_base(a) | a := v.alternatives[_]]
    result := l.choice(vs, v.tainted)
}

stmt_base(v) := scalar(v, "allow") if v.kind != "known"
stmt_base(v) := l.and(l.and(wild(v.action), wild(v.resource)), atom(v.effect, "allow")) if v.kind == "known"
stmt(v) := stmt_base(v) if v.kind != "one_of"
stmt(v) := result if {
    v.kind == "one_of"
    vs := [stmt_base(a) | a := v.alternatives[_]]
    result := l.choice(vs, v.tainted)
}

stmts_base(v) := scalar(v, "allow") if v.kind != "known"
stmts_base(v) := l.false_result if {
    v.kind == "known"
    v.type == "null"
}
stmts_base(v) := result if {
    v.kind == "known"
    v.type == "list"
    vs := [stmt(a) | a := v.elements[_]]
    result := l.any(vs)
}
stmts_base(v) := stmt(v.single) if {
    v.kind == "known"
    not v.type in {"list", "null"}
}
stmts(v) := stmts_base(v) if v.kind != "one_of"
stmts(v) := result if {
    v.kind == "one_of"
    vs := [stmts_base(a) | a := v.alternatives[_]]
    result := l.choice(vs, v.tainted)
}

doc_base(v) := scalar(v, "allow") if v.kind != "known"
doc_base(v) := stmts(v.statements) if v.kind == "known"
doc(v) := doc_base(v) if v.kind != "one_of"
doc(v) := result if {
    v.kind == "one_of"
    vs := [doc_base(a) | a := v.alternatives[_]]
    result := l.choice(vs, v.tainted)
}

policy_base(v) := scalar(v, "allow") if v.kind != "known"
policy_base(v) := l.false_result if {
    v.kind == "known"
    v.document == null
}
policy_base(v) := doc(v.document) if {
    v.kind == "known"
    v.document != null
}
policy(v) := policy_base(v) if v.kind != "one_of"
policy(v) := result if {
    v.kind == "one_of"
    vs := [policy_base(a) | a := v.alternatives[_]]
    result := l.choice(vs, v.tainted)
}
result := policy(input.policy)
