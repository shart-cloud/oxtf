# Benchmark notes (Q9)

## Exploratory per-repo Trivy timings (not final numbers)

Run 2026-10-14 while another agent was compiling on the same 4-core machine, so
the numbers are directional only. Command per repo:
`trivy config --quiet --skip-check-update --misconfig-scanners terraform --format json <repo>`
(trivy 0.76.0).

| Repo | Wall (s) |
| --- | ---: |
| Azure__terraform-azurerm-avm-res-storage-storageaccount | 1326.0 |
| terraform-google-modules__terraform-google-kubernetes-engine | 300.2 |
| Azure__terraform-azurerm-aks | 32.6 |
| terraform-aws-modules__terraform-aws-eks | 20.9 |
| terraform-google-modules__terraform-google-network | 19.6 |
| terraform-aws-modules__terraform-aws-rds | 16.2 |
| terraform-aws-modules__terraform-aws-lambda | 14.7 |
| terraform-aws-modules__terraform-aws-alb | 14.0 |
| terraform-aws-modules__terraform-aws-vpc | 11.1 |
| terraform-aws-modules__terraform-aws-s3-bucket | 8.8 |
| terraform-aws-modules__terraform-aws-rds-aurora | 8.6 |
| terraform-aws-modules__terraform-aws-autoscaling | 8.1 |
| terraform-google-modules__terraform-google-cloud-storage | 7.0 |
| terraform-aws-modules__terraform-aws-cloudfront | 6.6 |
| terraform-aws-modules__terraform-aws-ec2-instance | 4.3 |
| terraform-aws-modules__terraform-aws-iam | 4.1 |
| terraform-aws-modules__terraform-aws-security-group | 3.4 |

## Why the two outliers are slow

Not network. Trivy 0.76.0 has no offline flag for `config`, so I checked a
60-second `--debug` run on the GKE repo:

```
trivy config --debug --skip-check-update --misconfig-scanners terraform corpus/repos/terraform-google-modules__terraform-google-kubernetes-engine
```

145,950 log lines in 60 s; the only "download" mention is
"No downloadable checks were loaded as --skip-check-update is enabled". The top
message kinds were:

```
  79008 evaluator] Starting iteration module="root"
  22125 evaluator] Added module output
   7715 evaluator] Expanded block into
   5746 parser] Added file module="root"
   4659 evaluator] Context unchanged module="root"
```

So the time goes into Trivy's fixpoint evaluator re-iterating nested local
modules (the GKE and AVM repos call many submodules from many examples), not
into fetching remote modules. Note also that `timeout 60` (SIGTERM) did not stop
trivy; it needed SIGKILL.

Implication for the final benchmark: report Trivy's total both with and without
these two repos, so one pathological case doesn't decide the comparison.
