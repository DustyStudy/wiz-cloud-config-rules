# wiz-cloud-config-rules: design

Date: 2026-10-17
Status: approved for implementation planning

## Goal

A public library of Wiz custom Cloud Configuration Rules (CCRs) for AWS that:

1. encode an opinionated FedRAMP / NIST SP 800-53 baseline that Wiz built-in rules do not cover by default,
2. are proven by unit tests without a Wiz tenant, and
3. can be loaded into any future Wiz tenant either by pasting into the Wiz UI or with Terraform.

All content is written from public AWS, OPA and Wiz sources. Nothing comes from any employer.

## Success criteria

- Nine rules (below), each in its own folder with `policy.rego`, `policy_test.rego` and `rule.yaml`.
- `opa test --coverage` passes at 90% or higher; `opa check` passes in OPA v1 mode and `--v0-compatible` mode.
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
- **Wiz OPA version.** Unknown; handled by the dual-mode syntax check below.

## Rules (v0.1.0)

| ID | Fails when | Severity | 800-53 |
|---|---|---|---|
| `kms-cmk-rotation` | Enabled, customer-managed, symmetric KMS key has rotation off, or a rotation period over 365 days | HIGH | SC-12, SC-28 |
| `s3-deny-insecure-transport` | Bucket policy has no `Deny` on `s3:*` or `*` with `aws:SecureTransport` = `false` | HIGH | SC-8, SC-8(1) |
| `s3-default-encryption-cmk` | Default encryption is SSE-S3, or SSE-KMS with `alias/aws/s3` or no key ID | MEDIUM | SC-28, SC-12 |
| `s3-server-access-logging` | Server access logging is off | MEDIUM | AU-2, AU-12 |
| `s3-versioning-enabled` | Versioning status is not `Enabled` | MEDIUM | CP-9, SI-12 |
| `sg-no-public-management-ports` | Any ingress from `0.0.0.0/0` or `::/0` covers port 22 or 3389, including ranges and protocol `-1` | CRITICAL | SC-7, AC-17 |
| `ec2-imdsv2-required` | Instance `MetadataOptions.HttpTokens` is not `required` | HIGH | AC-3, CM-6 |
| `cloudtrail-integrity` | Trail lacks log file validation, a KMS key, or multi-region coverage | HIGH | AU-9, AU-9(3), AU-12 |
| `iam-github-oidc-trust-pinned` | Role trusting `token.actions.githubusercontent.com` does not require `aud` = `sts.amazonaws.com`, or its `sub` condition is missing or wildcards the repository part | CRITICAL | AC-3, AC-6, IA-8 |

Rule decisions:

- No rule matches on a hardcoded `arn:aws:` partition. Rule 9 identifies the OIDC provider by host, so all rules work in `aws-us-gov`.
- A KMS deletion window is not a property of a live key (it exists only while deletion is pending, and AWS enforces 7-30 days), so it is out of scope.
- `s3-default-encryption-cmk` cannot tell from a key ARN whether a key is AWS-managed; it fails only on the `aws/s3` alias or a missing key ID. Documented as a known limit.
- Skip cases: AWS-managed or asymmetric or disabled KMS keys; roles that do not trust the GitHub OIDC provider.

## Repository layout

```
rules/aws/<rule-id>/
  policy.rego         # pasted into Wiz or loaded by Terraform
  policy_test.rego    # package wiz_test
  rule.yaml
terraform/            # module
examples/basic/       # provider block + module call
tests/terraform/      # terraform test files (mock provider)
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
- Accept a policy document as a JSON string or an object; accept `Statement`, `Action` and condition values as a single item or a list.
- Syntax must pass `opa check` in v1 mode and in `--v0-compatible` mode. If OPA 1.x rejects the `future.keywords` imports, fall back to plain v0 syntax (as in public Wiz examples) and run all OPA commands with `--v0-compatible`.

## Tests

- `policy_test.rego` (package `wiz_test`) uses inline fixtures shaped like AWS API output.
- Each rule has at least: one pass case, one fail case per distinct failure condition, one skip case where a skip exists, and one assertion that `currentConfiguration` is set on failure.
- Required edge cases: port range spanning 22 (e.g. 20-25), protocol `-1`, IPv6 `::/0`, single-statement (object) policy, policy as a JSON string, a GovCloud ARN, `sub` values `repo:org/*`, `repo:org/*:*`, `repo:org/repo:*` and `repo:org/repo:ref:refs/heads/main`.
- CI: `opa fmt --fail`, dual-mode `opa check`, `opa test --coverage` with threshold 90.

## Terraform module

- Reads `fileset("${path.module}/../rules", "**/rule.yaml")`, `yamldecode`s each, and creates `wiz_cloud_configuration_rule` with `for_each` keyed by rule `id`.
- Maps: `name = "${var.name_prefix}${name}"`, `description`, `severity`, `opa_policy = file(policy.rego)`, `target_native_types` (override or YAML), `remediation_instructions`, `function_as_control`, `scope_account_ids`.
- Tags: `source = wiz-cloud-config-rules`, `rule_id = <id>`, one `nist-800-53 = <control>` tag per control.
- Requires `tf.app.wiz.io/wizsec/wiz >= 1.28` and Terraform `>= 1.9`. Does not configure the provider.
- Preconditions: severity is in the provider enum; `target_native_types` is non-empty; `id` matches its folder name.

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

`terraform test` uses `mock_provider "wiz"` and asserts: resource count equals rule folder count; exclusions remove resources; overrides replace native types; NIST tags are emitted per control; `opa_policy` equals the file contents.

A real `plan` or `apply` needs a tenant and is not run.

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

- Local clone `C:\repos\wiz-cloud-config-rules`; GitHub repo `DustyStudy/wiz-cloud-config-rules` created private.
- `main` holds the initial commit; all work lands in one PR from `feat/initial-rules`; the user merges.
- One Codex (Astra) review of the PR before merge, at most one confirmation pass.
- After merge: tag and release `v0.1.0`. Making the repo public is the user's decision.
- The implementation plan stays out of git via `.git/info/exclude`.

## Out of scope (v0.1.0)

- `iac_matchers` (planned v2: same checks against Terraform code in Wiz Code).
- Non-AWS clouds.
- Profile README link.
- Any live tenant run.
