# wiz-cloud-config-rules: design

Date: 2026-10-17
Status: draft, revised after peer review; pending owner review

## Goal

A public library of Wiz custom Cloud Configuration Rules (CCRs) for AWS that:

1. encode an opinionated FedRAMP / NIST SP 800-53 baseline, stricter than generic checks,
2. are proven by unit tests without a Wiz tenant, and
3. can be loaded into any future Wiz tenant either by pasting into the Wiz UI or with Terraform.

All content is written from public AWS, OPA and Wiz sources. Nothing comes from any employer.

## Success criteria

- Nine rules (below), each in its own folder with `policy.rego`, `policy_test.rego` and `rule.yaml`.
- Per rule directory (every rule is `package wiz`, so rules are never loaded together): `opa test --coverage --threshold 90` passes, and `opa check` passes in OPA v1 mode and `--v0-compatible` mode.
- A Terraform module creates one `wiz_cloud_configuration_rule` per rule folder; `terraform validate` and `terraform test` (mock provider) pass on Terraform 1.9.8 and 1.16.4.
- CI matches the DustyStudy standard (Checkov, Trivy, Gitleaks, zizmor, harden-runner, SHA-pinned actions, Dependabot with 7-day cooldown).
- README states what is verified and gives a short first-tenant check for what is not.

## Verified facts (2026-10-17)

- Official provider: `tf.app.wiz.io/wizsec/wiz`, latest 1.28.19776, downloadable without an account.
- Resource `wiz_cloud_configuration_rule`: required `name`; optional `description`, `enabled`, `function_as_control`, `opa_policy`, `remediation_instructions`, `scope_account_ids`, `scope_project_id`, `security_sub_categories`, `severity` (`INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), `target_native_types` (required when `opa_policy` is set), blocks `iac_matchers` and `tags` (`key`, `value`).
- Provider credentials: `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`; `environment` (`WIZ_ENVIRONMENT`) includes `gov` and `fedramp`.
- Rule contract (from public Wiz rule examples): `package wiz`, `result` is `"pass"`, `"fail"` or `"skip"`, plus `currentConfiguration` and `expectedConfiguration` strings.

## Unverified (needs a live tenant)

- **Native type names.** The `target_native_types` strings for each AWS resource are listed only in login-gated Wiz docs. `rule.yaml` holds a best guess; the module's `native_type_overrides` variable corrects them without a fork.
- **Input JSON shape.** Fixtures follow AWS API output (as public Wiz examples do). Wiz may nest or rename fields. Rules read fields defensively, but the first-tenant check must confirm each rule against one real resource.
- **Wiz OPA version and builtins.** Unknown. The dual-mode `opa check` (verified locally on OPA 1.21.2: `future.keywords` imports pass v1, v1 `--strict` and `--v0-compatible`) covers syntax, not which builtins Wiz's runtime supports. Rules stick to common builtins (`json.unmarshal`, `urlquery.decode`, `object.get`, `startswith`, `endswith`, `contains`, `regex.match`, `to_number`); the first-tenant check confirms them.

## Rules (v0.1.0)

| ID | Fails when | Severity | 800-53 |
|---|---|---|---|
| `kms-cmk-rotation` | An eligible key (see below) has rotation off or missing, or a rotation period over 365 days | HIGH | SC-12, SC-28 |
| `s3-deny-insecure-transport` | No bucket policy statement provides full insecure-transport denial (see below), or the policy is missing or unparseable | HIGH | SC-8, SC-8(1) |
| `s3-default-encryption-cmk` | Default encryption is missing, SSE-S3 (`AES256`), or SSE-KMS / DSSE-KMS (`aws:kms`, `aws:kms:dsse`) with no key ID or an `aws/s3` alias in any form | MEDIUM | SC-28, SC-12 |
| `s3-server-access-logging` | `LoggingEnabled` is missing or has no `TargetBucket` | MEDIUM | AU-2, AU-12 |
| `s3-versioning-enabled` | Versioning `Status` is missing (never enabled) or not `Enabled` | MEDIUM | CP-9 |
| `sg-no-public-management-ports` | Any ingress rule from `0.0.0.0/0` or `::/0` reaches port 22 or 3389 over TCP or UDP, or allows all traffic (`-1`) | CRITICAL | SC-7, AC-17 |
| `ec2-imdsv2-required` | Metadata endpoint is enabled and `HttpTokens` is missing or not `required` | HIGH | AC-3, CM-6 |
| `cloudtrail-integrity` | Trail lacks log file validation, a KMS key, or multi-region coverage | HIGH | AU-9, AU-9(3), AU-12 |
| `iam-github-oidc-trust-pinned` | Any statement that lets the GitHub OIDC provider assume the role is not pinned (see below), or the trust policy is unparseable | CRITICAL | AC-3, AC-6, IA-8 |

800-53 mappings are partial evidence for those controls, not full implementation; the README says so.

### Rule details

- **Missing data never passes.** In Rego a comparison on a missing field is undefined, which would fall through to the default `pass`. Every rule reads fields with `object.get` and an explicit default, and each rule has a test with the field absent.
- **Policy documents** (S3 bucket policy, IAM trust policy) may arrive as an object, a JSON string, or a URL-encoded JSON string (IAM `GetRole` returns RFC 3986-encoded documents). Rules decode URL-encoding when the string does not start with `{`, then parse. A document that is present but cannot be parsed is a `fail` with its own message, never a `skip` or `pass`. `Statement`, `Action`, `Principal` values and condition values may be a single item or a list.
- **`kms-cmk-rotation`.** Eligible: `KeyManager` = `CUSTOMER`, `KeyState` = `Enabled`, `KeySpec` = `SYMMETRIC_DEFAULT`, `Origin` = `AWS_KMS` (automatic rotation is unsupported for imported material, custom key stores and HMAC/asymmetric keys). Anything else is `skip`. Input is the combined `DescribeKey.KeyMetadata` plus `GetKeyRotationStatus` fields (`KeyRotationEnabled`, `RotationPeriodInDays`); a missing period with rotation on passes (AWS default 365). Tests cover 365 (pass), 366 (fail), missing period, and missing `KeyRotationEnabled` (fail).
- **`s3-deny-insecure-transport`.** A statement counts only if all hold: `Effect` = `Deny`; `Principal` is `"*"` or `{"AWS": "*"}`; `Action` includes `s3:*` or `*`; `Resource` covers both the bucket and its objects (`arn:<any partition>:s3:::<bucket>` and `.../<bucket>/*`, or `*`), matched by suffix so no partition is hardcoded; its only condition is `Bool` (or `BoolIfExists`) `aws:SecureTransport` = `false`, or `NumericLessThan` `s3:TlsVersion` with a value of at least 1.2. Extra conditions narrow the denial, so a statement carrying them does not count.
- **`s3-default-encryption-cmk`.** `aws/s3` is detected as `alias/aws/s3` or an ARN ending in `:alias/aws/s3` (any partition). Limit (documented): an opaque key ID or key ARN cannot prove customer ownership from the bucket alone, so it passes.
- **S3 logging and versioning** skip directory buckets (name ends in `--x-s3`), which support neither feature.
- **`sg-no-public-management-ports`.** Protocol is normalized (`tcp`/`6`, `udp`/`17`, `-1`/`all`). Port fields are only compared for TCP and UDP; ICMP and other protocols are ignored; `-1` fails without reading ports. UDP is included because RDP also listens on UDP 3389. IPv4 (`IpRanges[].CidrIp`) and IPv6 (`Ipv6Ranges[].CidrIpv6`) are each tested on their own.
- **`ec2-imdsv2-required`.** `HttpEndpoint` = `disabled` passes (no IMDS exposure).
- **`cloudtrail-integrity`** checks configuration only. It does not prove the trail is logging (`GetTrailStatus.IsLogging` is not a trail field) or which events are selected; the README says so.
- **`iam-github-oidc-trust-pinned`.** A statement is relevant if `Effect` = `Allow`, `Action` includes `sts:AssumeRoleWithWebIdentity` (or `sts:*` / `*`), and `Principal.Federated` (string or list) contains an ARN ending in `:oidc-provider/token.actions.githubusercontent.com`. No relevant statement means `skip`. Every relevant statement must, through its conditions:
  - require `token.actions.githubusercontent.com:aud` = `sts.amazonaws.com` (`StringEquals`, every value exactly that), and
  - constrain `token.actions.githubusercontent.com:sub` under `StringEquals` or `StringLike` (including `ForAnyValue:` forms), where every value names a concrete owner and repository (`repo:<owner>/<repo>:...`). Under `StringLike`, a `*` or `?` in the owner or repository part fails; wildcards after the repository (branch, environment) are allowed. Under `StringEquals`, `*` is literal and cannot widen access.
  Values within one condition key are OR'd, so one loose value fails the statement. One safe statement never offsets a loose one.
- No rule matches on a hardcoded `arn:aws:` partition, so all rules work in `aws-us-gov`.
- A KMS deletion window is not a property of a live key (it exists only while deletion is pending, and AWS enforces 7-30 days), so it is out of scope.

## Repository layout

```
rules/aws/<rule-id>/
  policy.rego         # pasted into Wiz or loaded by Terraform
  policy_test.rego    # package wiz_test
  rule.yaml
terraform/            # module
terraform/tests/      # terraform test files (mock provider); run from terraform/
examples/basic/       # provider block + module call
docs/design/          # this spec
.github/workflows/    # ci.yml, security-scan.yml
```

### `rule.yaml` schema

```yaml
id: s3-deny-insecure-transport          # equals the folder name
name: S3 bucket policy denies insecure transport
description: <one or two sentences>
severity: HIGH                          # provider enum
target_native_types: [<native type>]    # best guess; see Unverified
nist_800_53: [SC-8, SC-8(1)]
remediation: <markdown, may include a Terraform snippet>
```

## Rego conventions

```rego
package wiz

import future.keywords.if
import future.keywords.in

default result := "pass"

result := "skip" if { <out of scope> }
else := "fail" if { <violation> }

currentConfiguration := <specific finding> if result == "fail"
expectedConfiguration := "<requirement in one sentence>"
```

- Each `policy.rego` is self-contained (no shared library), so a single file can be pasted into Wiz. Duplication between S3 policy rules is accepted.
- Input handling follows "Rule details" above (missing data never passes; policy documents decoded from object, JSON string or URL-encoded string).
- Syntax must pass `opa check` in v1 mode and in `--v0-compatible` mode (verified feasible on OPA 1.21.2).

## Tests

- `policy_test.rego` (package `wiz_test`) uses inline fixtures shaped like AWS API output.
- Each rule has at least: one pass case, one fail case per distinct failure condition, one skip case where a skip exists, and one assertion that `currentConfiguration` is set on failure.
- Every rule has a test with its key field absent, proving missing data does not pass.
- Required edge cases: port range spanning 22 (e.g. 20-25), UDP 3389, ICMP ignored, protocol `-1`, IPv6 `::/0` alone; single-statement (object) policy, policy as a JSON string, as a URL-encoded string, malformed, and missing; deny scoped to one principal, to objects only, or with an extra condition (none count); a GovCloud ARN; directory bucket skip; KMS imported-material and HMAC skip; IMDS endpoint disabled; `sub` values `repo:org/*`, `repo:org/*:*`, `repo:*/repo:*`, `repo:org/repo:*`, `repo:org/repo:ref:refs/heads/main`; a literal `*` under `StringEquals`; one safe plus one loose `sub` value; one safe plus one loose statement.
- CI: `opa fmt --fail` across `rules/`; then, for each rule directory separately, dual-mode `opa check` and `opa test --coverage --threshold 90`.

## Terraform module

- Reads `fileset("${path.module}/../rules", "**/rule.yaml")` (results are relative, so each path is re-prefixed before `file()`), `yamldecode`s each, and creates `wiz_cloud_configuration_rule` with `for_each` keyed by rule `id`.
- Maps: `name = "${var.name_prefix}${name}"`, `description`, `severity`, `opa_policy = file(policy.rego)`, `target_native_types` (override or YAML), `remediation_instructions`, `function_as_control`, `scope_account_ids`.
- Tags (emitted as `tags` blocks with `dynamic`): `source = wiz-cloud-config-rules`, `rule_id = <id>`, and one `nist-800-53` tag whose value is the comma-joined control list (e.g. `SC-8, SC-8(1)`). One tag rather than one per control, because whether the Wiz API accepts repeated keys is unknown. Tags are labels only; they do not associate the rule with a Wiz security framework (`security_sub_categories` does that and is out of scope).
- Requires `tf.app.wiz.io/wizsec/wiz >= 1.28` and Terraform `>= 1.9`. Does not configure the provider.
- Preconditions: severity is in the provider enum; `target_native_types` (after overrides) is non-empty and has no empty strings; `id` matches its folder name. Variable validation rejects override keys that are not rule IDs.

| Variable | Type | Default | Purpose |
|---|---|---|---|
| `exclude_rules` | `set(string)` | `[]` | Disable rules by ID |
| `scope_account_ids` | `set(string)` | `null` | Limit to accounts; null means all |
| `function_as_control` | `bool` | `false` | Also create Issues, not only findings |
| `name_prefix` | `string` | `"Custom - "` | Distinguish from built-ins |
| `native_type_overrides` | `map(list(string))` | `{}` | Correct native types per rule ID |

Outputs: `rule_ids` (map of rule ID to Wiz rule ID).

Usage from another repository:

```hcl
module "wiz_rules" {
  source = "git::https://github.com/DustyStudy/wiz-cloud-config-rules.git//terraform?ref=v0.1.0"
}
```

`examples/basic` shows the provider block with credentials from environment variables and a comment for `environment = "gov"` / `"fedramp"`.

`terraform test` (files in `terraform/tests/`, run from `terraform/`) uses `mock_provider "wiz"` and asserts: resource count equals rule folder count; exclusions remove resources; overrides replace native types; the NIST tag carries the control list; `opa_policy` equals the file contents. Negative tests use `expect_failures` for an empty override and an unknown override key.

Mocking proves the module's wiring, not that the Wiz API accepts the values. A real `plan` or `apply` needs a tenant and is not run.

## CI and repository standard

- `ci.yml`: Rego job (OPA installed as a checksum-pinned binary); Terraform job matrix 1.9.8 and 1.16.4 (`fmt -check`, `init -backend=false`, `validate`, `test`); zizmor job (`--min-severity medium`).
- `security-scan.yml`: Checkov, Trivy, Gitleaks.
- harden-runner (audit) first in every job; actions pinned by SHA; Dependabot for `github-actions` and `terraform` with a 7-day cooldown.
- `.gitattributes` forcing LF line endings.
- After the first merge: `main` protection matching fedramp-terraform-library (required checks strict, `enforce_admins`, linear history, conversation resolution, no force-push or delete); delete branch on merge; wiki and projects off.

## Docs

- README: summary; rule table with 800-53 controls; quickstart for paste and for Terraform; adding a rule; validation status (verified by `opa test` and `terraform test`, plus the first-tenant check: confirm native types, run each rule's test against one real resource, set `native_type_overrides`); a mermaid diagram (rule folder → `opa test` → Terraform → Wiz).
- LICENSE (MIT), SECURITY.md, CHANGELOG.md.
- No employer references; no job-search wording.

## Delivery

- Local clone `C:\repos\wiz-cloud-config-rules`. Everything is built and verified locally first (`opa`, `terraform test`, Checkov, Trivy, Gitleaks, zizmor run on the workstation).
- Private-repo Actions minutes are exhausted for the month, so a private repo cannot run CI. The GitHub repo is created only on the user's go, as public (free Actions) unless the user decides otherwise.
- Codex (Astra) reviewed this spec on 2026-10-17 (16 findings; 15 applied, the CI-scope finding declined to keep the repo consistent with the owner's portfolio standard). One more review of the finished local branch before anything is pushed; at most one confirmation pass.
- `main` holds the initial commit; all work lands in one PR from `feat/initial-rules`; the user merges.
- After merge: tag and release `v0.1.0`. Making the repo public is the user's decision.
- The implementation plan stays out of git via `.git/info/exclude`.

## Out of scope (v0.1.0)

- `iac_matchers` (planned v2: same checks against Terraform code in Wiz Code).
- Non-AWS clouds.
- Profile README link.
- Any live tenant run.
