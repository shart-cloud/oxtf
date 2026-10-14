package oxtf.gcp_storage
import rego.v1
import data.oxtf.boolean.verdict

result := {"rank": 0, "evidence": null} if input.effective.kind == "missing"
result := verdict(input.effective) if input.effective.kind != "missing"
