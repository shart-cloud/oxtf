package oxtf.rds
import rego.v1
import data.oxtf.boolean.verdict

replica if { input.replica.kind != "missing"; input.replica.kind != "null" }
result := {"rank": 0, "evidence": null} if replica
result := {"rank": 0, "evidence": null} if {
    not replica
    input.effective.kind == "missing"
}
result := verdict(input.effective) if {
    not replica
    input.effective.kind != "missing"
}
