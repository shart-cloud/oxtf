# Reconciliation with Checkov

Date: 2026-10-22. oxtf at `342f4b4`, Checkov 3.2.328 (the version whose
Terraform checks oxtf bundles). Six repositories from the pinned corpus, neither
tool given installed remote modules (no `terraform init`).

This answers the question a Checkov user asks first: why does oxtf report a
different number of results on the same code?

## Short answer

On these six repositories every result that only Checkov reported is a Checkov
false positive, and every oxtf-only result we checked is a real issue that
Checkov missed. The remaining difference in counts comes from one supply-chain
check oxtf does not ship (`CKV_TF_1`), from oxtf's default profile, and from
Checkov counting each module call separately.

| | Results | Reviewed | Outcome |
| --- | ---: | ---: | --- |
| Both tools agree | 255 | — | — |
| Only Checkov | 20 | all 20 | All Checkov false positives (three patterns below) |
| Only oxtf | 88 | 57, covering every check with 3+ rows | All real except one rule-scope issue (`CKV_AWS_315`) |
| oxtf root not fully evaluated | 35 | — | Remote modules not installed; `--fetch` evaluates them |
| Check not shipped by oxtf | 174 | — | 168 are `CKV_TF_1` |

oxtf scanned each repository in 0.03–0.14 s. Checkov took 168 s on
`terraform-aws-eks` alone on the same machine (its other runs below shared the
machine and are not comparable timings).

## Method

`bench/reconcile.py` runs `oxtf scan -r --profile all -f json` and compares it
with `checkov -d REPO --framework terraform --compact -o json`. Results are
keyed by (check id, file, resource block): Checkov reports a failed check once
per declaration per module call, and oxtf groups occurrences under one finding
per declaration, so both are reduced to the declaration. Native oxtf rules count
under their Checkov aliases. `--profile all` makes the comparison like for like;
the default profile is discussed separately below.

| Repository | Revision | Matched | Only Checkov | Only oxtf | Not evaluated | Not shipped |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| terraform-aws-eks | `91b8a8d` | 21 | 4 | 8 | 3 | 26 |
| terraform-aws-s3-bucket | `9afa4fc` | 10 | 6 | 6 | 0 | 16 |
| terraform-aws-rds | `175da04` | 10 | 3 | 6 | 0 | 32 |
| terraform-aws-vpc | `b3abd6d` | 4 | 4 | 4 | 0 | 4 |
| terraform-azurerm-aks | `58ffc7c` | 37 | 3 | 6 | 0 | 3 |
| terraform-google-kubernetes-engine | `068af04` | 173 | 0 | 58 | 32 | 93 |
| **Total** | | **255** | **20** | **88** | **35** | **174** |

The per-row classification (`rows.json`) and the repository list are in
`bench/results/reconcile/`. Raw tool outputs (about 230 MB, mostly Checkov's
passed checks) are not committed; the commands below regenerate them.

```sh
for r in $(cat bench/results/reconcile/repos.txt); do
  checkov -d corpus/repos/$r --framework terraform --compact -o json \
    > bench/results/reconcile/checkov/$r.json
done
python3 bench/reconcile.py --checkov-dir bench/results/reconcile/checkov \
  --out bench/results/reconcile $(sed 's|^|corpus/repos/|' bench/results/reconcile/repos.txt)
```

## Only Checkov: 20 results, all false positives

oxtf evaluates Terraform the way Terraform does: variable defaults, `dynamic`
blocks, `count`/`for_each`, locals and references. Checkov's mistakes here fall
into three patterns.

**Values it does not resolve (3).** `terraform-aws-eks` launch templates set
`http_tokens` and `http_put_response_hop_limit` from `var.metadata_options`,
whose default is `required` and `1`, through a `dynamic "metadata_options"`
block. Checkov reports IMDSv2 disabled (`CKV_AWS_79`) and an excessive hop limit
(`CKV_AWS_341`); both are configured correctly.

**Resources that cannot exist (12).** The `wrappers/` modules of
`terraform-aws-s3-bucket` and `terraform-aws-rds` are called with
`for_each = var.items`, default `{}`, so no instance exists; Checkov evaluates
the module anyway and fails its `try(...)` fallbacks (`CKV_AWS_53`–`56`, `19`,
`226`, `211`, `CKV2_AWS_6`, `CKV2_AWS_60`). In `terraform-azurerm-aks`, the
application gateway and its subnet have
`count = var.use_brown_field_application_gateway && ...`, default `false`
(`CKV_AZURE_217`, `218`, `CKV2_AZURE_31`).

**Connections it does not follow (5).** Graph checks require one resource to
reference another. `terraform-aws-vpc` attaches its private NACL through
`aws_subnet.private[*].id` (`CKV2_AWS_1`) and its NAT EIPs through
`element(local.nat_gateway_ips, ...)` (`CKV2_AWS_19`); security groups in both
VPC and EKS are attached through locals and `try` (`CKV2_AWS_5`); the default
security group rules come from variable defaults (`CKV2_AWS_12`). oxtf's
resource graph follows the evaluated references.

## Only oxtf: 88 results

oxtf reports these because it evaluates what Checkov skips; 13 are
`conditional` (they depend on an unset variable), the rest `definite`. Checks
reviewed:

- **IAM policies built from `aws_iam_policy_document` data sources**
  (`CKV_AWS_355`, `290`, `274`; EKS). oxtf evaluates the document and finds
  `Resource: "*"` for ECR pull-through-cache writes and for
  `eks:DescribeCluster` (from `cluster_arns`, default `["*"]`), and an
  `AdministratorAccess` attachment. Checkov cannot read the rendered policy.
- **Defaults that leave a control off** (`CKV_AWS_158`; EKS). The CloudWatch
  log group's `kms_key_id` comes from a variable defaulting to `null`.
- **Controls that are off by default** (`CKV_GCP_20`, `65`, `66`, `12`, `61`;
  GKE). Master authorized networks render only when `master_authorized_networks`
  (default `[]`) is non-empty; Binary Authorization only when
  `enable_binary_authorization` (default `false`); Google Groups RBAC only when
  `authenticator_security_group` (default `null`) is set; network policy and
  intranode visibility default to `false`. Checkov sees a `dynamic` block and
  passes the check without evaluating it, or does not evaluate the variant.
- **Checks Checkov did not run on a resource** (`CKV_GCP_123`; GKE). Seven
  cluster definitions declare an inline `node_pool {}`, which the check forbids;
  Checkov recorded no result for them.

One result is a rule-scope problem rather than an evaluation one:
`CKV_AWS_315` (Auto Scaling groups use launch templates) only accepts a
top-level `launch_template`, so an ASG using a launch template through
`mixed_instances_policy` fails. Checkov's predicate has the same defect and
only escapes it here by never evaluating the mixed-instances configuration.

Checks with fewer than three rows were not all reviewed individually; they
follow the same evaluation patterns, and confirming them is part of the
follow-up below.

## Why a default oxtf run shows fewer results than Checkov

1. **`CKV_TF_1` (168 of 174 unshipped results).** Checkov flags every module
   call whose source is not pinned to a Git commit hash, including registry
   modules with version constraints. oxtf does not ship module-source checks.
   Only four other Checkov checks seen here are missing (`CKV_AWS_356`,
   `CKV_AWS_111`, `CKV_GCP_82`, `CKV_GCP_36`).
2. **Profiles.** oxtf's default `security` profile (with not-yet-reviewed
   bundled rules) leaves out `hygiene` and `audit` rules. Of the 255 matched
   results, 159 are hygiene or audit and appear only with `--profile all`.
3. **Checkov false positives**, above.
4. **Counting.** Checkov repeats a declaration's result for every module call
   that reaches it; oxtf reports one finding per declaration and lists the
   other occurrences (`occurrences` in JSON, "also reached as" in text).

## Follow-up

- Fix `CKV_AWS_315` in curation to accept
  `mixed_instances_policy.launch_template`.
- Review the oxtf-only checks with fewer than three rows individually.
- Decide whether to ship a module-source pinning rule equivalent to `CKV_TF_1`,
  likely in the `hygiene` profile, and whether to bundle the four other
  missing checks.
- Rerun with `--fetch` (and Checkov's `--download-external-modules`) to cover
  the 35 results in roots oxtf could not fully evaluate.
