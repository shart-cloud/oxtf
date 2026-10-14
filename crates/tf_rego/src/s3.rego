package oxtf.s3
import rego.v1
import data.oxtf.lattice as l
import data.oxtf.boolean.verdict

flags(p) := result if {
    vs := [verdict(v) | v := p.flags[_]]
    result := l.any(vs)
}
permissive(p) := l.or(flags(p), {"rank":2,"evidence":null,"reason":"pab_existence"}) if p.existence == "tainted"
permissive(p) := flags(p) if p.existence != "tainted"
matching := [permissive(p) | p := input.candidates[_]; p.match == "yes"]
maybe if { some p in input.candidates; p.match == "maybe" }
result := {"rank":3,"evidence":null,"reason":"missing_protection"} if { count(matching) == 0; not maybe }
result := l.false_result if { count(matching) == 0; maybe }
result := matching[i] if {
    count(matching) > 0
    best := min([v.rank | v := matching[_]])
    i := min([j | matching[j].rank == best])
}
