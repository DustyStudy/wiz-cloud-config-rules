# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- `s3-deny-insecure-transport`: a `NumericLessThan` `s3:TlsVersion` denial no
  longer counts, because plain HTTP requests carry no TLS version and are not
  denied by it; `NumericLessThanIfExists` still counts. Bucket and object
  denials may now sit in separate statements, actions and condition keys are
  matched without regard to case, and directory buckets are skipped.
- `s3-default-encryption-cmk`: skips directory buckets and server access log
  destinations, found by a bucket policy that lets `logging.s3.amazonaws.com`
  put objects in the bucket (S3 delivers access logs only to SSE-S3 buckets).
- `sg-no-public-management-ports`: an ingress entry with no protocol is
  treated as all traffic instead of being ignored.
- `iam-github-oidc-trust-pinned`: one operator that pins `aud` or `sub` is
  enough, since IAM ANDs operators; an exact `aud` under `StringLike` and
  condition keys in any case are accepted.

### Changed

- The module checks `native_type_overrides` keys in variable validation and
  no longer creates a `terraform_data` resource for it. Empty native type
  strings in `rule.yaml` are rejected.
- `scripts/check-rules.sh` writes coverage to a temporary file.

## [0.1.0] - 2026-10-17

### Added

- Nine Wiz custom Cloud Configuration Rules for AWS, each with `opa test`
  cases and NIST SP 800-53 mappings: `kms-cmk-rotation`,
  `s3-deny-insecure-transport`, `s3-default-encryption-cmk`,
  `s3-server-access-logging`, `s3-versioning-enabled`,
  `sg-no-public-management-ports`, `ec2-imdsv2-required`,
  `cloudtrail-integrity`, `iam-github-oidc-trust-pinned`.
- Terraform module that creates one `wiz_cloud_configuration_rule` per rule
  folder, with exclusions, account scoping, native type overrides and
  `terraform test` coverage.
- CI for Rego (OPA v1 and v0-compatible checks, tests with coverage) and
  Terraform 1.9.8 and 1.16.4, plus Gitleaks, Checkov, Trivy and zizmor.

[Unreleased]: https://github.com/DustyStudy/wiz-cloud-config-rules/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DustyStudy/wiz-cloud-config-rules/releases/tag/v0.1.0
