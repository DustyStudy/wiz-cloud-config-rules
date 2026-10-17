# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
