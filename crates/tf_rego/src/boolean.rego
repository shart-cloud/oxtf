package oxtf.boolean
import rego.v1

# Native not_true semantics, including Terraform boolean strings.
scalar(v) := 0 if { v.kind == "known"; v.boolean == true }
scalar(v) := 3 if { v.kind == "known"; v.boolean != true }
scalar(v) := 1 if v.kind == "unknown"
scalar(v) := 2 if v.kind == "tainted"

verdict(v) := {"rank": scalar(v), "evidence": v.handle} if v.kind != "one_of"
verdict(v) := {"rank": 0, "evidence": null} if {
    v.kind == "one_of"
    count(v.alternatives) == 0
}
verdict(v) := {"rank": 3, "evidence": v.alternatives[0].handle} if {
    v.kind == "one_of"
    count(v.alternatives) > 0
    every a in v.alternatives { scalar(a) == 3 }
}
verdict(v) := {"rank": combined, "evidence": v.alternatives[index].handle} if {
    v.kind == "one_of"
    ranks := [scalar(a) | a := v.alternatives[_]]
    count(ranks) > 0
    not all_true(ranks)
    best := max(ranks)
    index := max([i | ranks[i] == best])
    combined := mixed_rank(best, v.tainted, ranks)
}
all_true(ranks) if { every rank in ranks { rank == 3 } }
mixed_rank(best, tainted, ranks) := best if best < 2
mixed_rank(best, tainted, ranks) := 2 if { best >= 2; tainted }
mixed_rank(best, tainted, ranks) := 2 if { best >= 2; not tainted; 2 in ranks }
mixed_rank(best, tainted, ranks) := 1 if { best >= 2; not tainted; not 2 in ranks }

