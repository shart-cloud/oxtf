# oxtf

A Rust Terraform security analyzer with a CLI and Python bindings
(`tfscan`). It evaluates HCL, local modules, and installed remote modules into
an abstract model, then runs native rules, a bundled Checkov catalog, and optional Rego
policies. Findings retain source provenance and stable fingerprints.

```sh
cargo build --locked -p tf_cli
target/debug/oxtf scan ./terraform --format json
```

Coding agents (Claude Code, Codex) can drive the scan-and-fix loop with the
[oxtf skill](skills/oxtf/SKILL.md): copy `skills/oxtf/` into the agent's skills
directory. `scripts/demo-fix-loop.sh` runs the same loop on pinned public modules.

CLI, Python, and Rust `ScanRequest::dirs()` / `ScanRequest::plan()` scans default
to the bundled Checkov catalog plus native seed rules in the security profile.
Rust callers can explicitly set `request.catalog = Catalog::seed()` for only
the seed rules. `Catalog::default()` is an empty catalog for custom rules.

Catalog work prioritizes signal quality over additional rules. Reviewed rules
include a severity rationale, remediation steps, and provider documentation in
the rule metadata; CLI text and SARIF also show that guidance. Public endpoints,
missing guardrails, and customer-managed-key requirements are distinguished
from public data access, administrative grants, and missing baseline encryption.
The reviewed scope and remaining metadata work are in
[the signal plan](docs/plans/SIGNAL_PLAN.md).

Source analysis handles `.tf`, `.tf.json`, and HCL/JSON variable files. It loads
`terraform.tfvars`, then `terraform.tfvars.json`, then both auto-file formats
in lexical order, then explicit `--var-file` arguments in order.
JSON variable strings are literal, including `${...}`.

Source evaluation supports `file`, `filebase64`, `templatefile`, file hashes,
string hashes, and `abspath`. File reads use the scan's overlays and resolve
relative paths against each scanned root. Templates retain source provenance,
unknown values and sensitivity; recursive template calls are rejected.
Explicitly fetched packages cannot read outside their recorded package boundary.
Unhandled expression errors make analysis fail; `try` and `can` can handle
ordinary evaluation errors, while coverage limits remain visible.

JSON configuration follows Terraform's context-dependent mapping: ordinary
strings are templates, single interpolations preserve their result type, and
literal-only fields (including variable defaults) stay literal. Mixed-format
modules, schema-defined nested blocks, and JSON-only installed modules use the
same loader. Locations refer to original JSON bytes, including escaped strings.

Override files (`override.tf`, `override.tf.json`, and `*_override` equivalents)
are composed in filename order before evaluation. Effective attributes keep
their original files, and HCL fixes target the winning assignment. JSON edit
hints are suppressed until a format-aware writer is available.

Remote modules are read offline from Terraform's installed-module manifest
at `.terraform/modules/modules.json`. Install them with `oxtf fetch` or
Terraform before scanning. For a custom data directory, pass `--data-dir DIR` or Python
`data_dir=...`; relative paths are resolved against each scanned root.
If your Terraform workflow uses `TF_DATA_DIR`, pass that directory explicitly.
The same option applies to plan source mapping and fix verification.

```sh
target/debug/oxtf scan ./terraform --data-dir .terraform --var-file ./production.tfvars.json
```

Source and version mismatches, missing installations, and nonliteral module
sources or version constraints produce coverage diagnostics. Installed
findings include package metadata and the module-call chain. Their fingerprints
are independent of cache location, and automatic fixes exclude cache files.
Terraform's manifest alone does not lock or verify Git content.

Known `count` values expand into numeric resource and module instances, including
`count.index`, indexed references, outputs, and splats. Each declaration expands
up to 64 instances; a root has a combined resource/module budget of 16,384.
Larger expansions report coverage gaps, and unknown counts stay abstract.
Invalid counts are errors. Regex matching and replacement are bounded too.

Fetch dependencies explicitly:

```sh
target/debug/oxtf fetch ./terraform
target/debug/oxtf fetch ./terraform --refresh
```

```python
import tfscan

dependencies = tfscan.fetch("./terraform", data_dir=".terraform")
result = tfscan.scan("./terraform", data_dir=".terraform")
```

Fetching supports registry version constraints, `git::https://`, `git::ssh://`,
`git::file://`, GitHub shorthand, `?ref=...`, and package subdirectories.
Registry downloads can point to Git or TAR, gzip-compressed TAR, and ZIP archives.
Sources and version constraints must be literal strings. Git submodules, links
inside archives, other transports, and other Git query parameters are rejected.
HTTP archive download URLs do not support go-getter's subdirectory or
wrapper-directory conventions; use a subdirectory in the module source address.

Cached packages are read-only snapshots, named by their content digest. The
manifest records the Git commit or an extracted-content SHA-256 revision.
An ordinary fetch verifies and reuses existing snapshots without contacting
their sources; `--refresh` resolves refs and versions again while retaining old
snapshots. The manifest changes atomically after all dependencies succeed.
Damaged snapshots are rejected; restore or remove the damaged cache before
fetching again. Ordinary scans read the recorded revision without rehashing
package contents.

Git uses installed credential helpers or an SSH agent. Registry authentication
uses `TF_TOKEN_<hostname>` (dots become `_`, hyphens become `__`). Credentials in
source URLs are rejected, and registry tokens are not forwarded across origins.
For a private service origin, use `--registry HOST=URL` or Python
`registry_origins={host: url}`. HTTPS is required except for loopback fixtures.

Default fetch limits are 64 MiB downloaded/staged Git data per package,
128 MiB extracted content, 10,000 entries per package, 256 module calls,
10 levels of child modules, five HTTP redirects, and a 120-second network/process
deadline per operation. Rust callers can configure `FetchRequest.limits`.
Archive paths, sizes, entry types, and local-module containment are checked.
Unix Git subprocesses also receive a file-size limit and are stopped as a
process group when a bound is exceeded.

Use plan input when concrete planned values are available. Unavailable modules
and bounded evaluation/expansion limits produce coverage diagnostics and an
`incomplete` scan status.

Runtime evaluation and cached override-default preparation each default to
1,000,000 steps per root. Child modules share their root's allowances, with
equivalent default-preparation charges on cache hits and misses. Scans also bound
input payloads, discovery, and Rego execution time, and release backend caches
when each root finishes. Configure
them with `--limits PATH` (JSON), Python's
`limits` argument, or Rust's `ScanRequest.limits`. See [limits](docs/LIMITS.md)
for examples, measured defaults, and accounting scope.

`complete` means the selected analysis ran without reported failures or
coverage gaps. It does not mean the configuration is secure, every value
is known, or every upstream Checkov check is supported. The bundled
catalog's manifest lists translation coverage.

CLI exit codes are 0 (no finding meets the threshold), 1 (findings meet the
threshold), 2 (scan could not start), and 3 (incomplete/failed analysis).
Exit 3 takes precedence, including with `--fail-on never`.

See [finding and output contracts](docs/FINDING_SCHEMA.md),
[domain concepts](CONTEXT.md), and [validation](docs/VALIDATION.md).
