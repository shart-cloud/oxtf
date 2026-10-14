package oxtf.lattice
import rego.v1

false_result := {"rank": 0, "evidence": null}
# AND/OR retain the left witness on ties. exists starts with FALSE/no witness.
and(a, b) := b if b.rank < a.rank
and(a, b) := a if b.rank >= a.rank
or(a, b) := b if b.rank > a.rank
or(a, b) := a if b.rank <= a.rank
any(vs) := false_result if count(vs) == 0
any(vs) := false_result if {
    count(vs) > 0
    max([v.rank | v := vs[_]]) == 0
}
any(vs) := vs[i] if {
    best := max([v.rank | v := vs[_]])
    best > 0
    i := min([j | vs[j].rank == best])
}
choice(vs, tainted) := false_result if count(vs) == 0
choice(vs, tainted) := vs[0] if {
    count(vs) > 0
    every v in vs { v.rank == 3 }
}
choice(vs, tainted) := {"rank": rank, "evidence": vs[i].evidence} if {
    count(vs) > 0
    not all_true(vs)
    best := max([v.rank | v := vs[_]])
    i := max([j | vs[j].rank == best])
    rank := mixed(best, tainted, vs)
}
all_true(vs) if {
    every v in vs { v.rank == 3 }
}
mixed(best, tainted, vs) := best if best < 2
mixed(best, tainted, vs) := 2 if {
    best >= 2
    tainted
}
mixed(best, tainted, vs) := 2 if {
    best >= 2
    not tainted
    some v in vs
    v.rank == 2
}
mixed(best, tainted, vs) := 1 if {
    best >= 2
    not tainted
    not has_taint(vs)
}
has_taint(vs) if {
    some v in vs
    v.rank == 2
}

