# Foreign policies used in tests

`conftest_hcl2_deny.rego` is an unmodified copy of
`examples/hcl2/policy/deny.rego` from
https://github.com/open-policy-agent/conftest at commit
`688c88f895842a1db5eed32841a82784537cc494` (2025-04-12), Apache-2.0.
SHA-256: `822b1c1902c6597aa596ecb0d83ae29d2fb1bbb7a4b41ce2db58c524b0a97dd7`.
It is run unchanged over oxtf's HCL-shaped projection as the exit check for
the foreign-policy seam.
