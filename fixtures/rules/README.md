# Seed rule fixtures

One directory per rule, one Terraform module directory per case. Each case has an
`EXPECT` file: one line per expected finding, `<rule-id> <resource-address> <severity>`,
where severity is `definite` (insecure as written) or `conditional` (insecure
depending on an unconstrained variable). Lines starting with `#` are notes. An empty
`EXPECT` means the case must produce no findings for that rule.

Case name prefixes: `fail_` (definite finding), `conditional_` (conditional
finding), `pass_` (no finding).
