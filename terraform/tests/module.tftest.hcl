mock_provider "wiz" {}

run "creates_every_rule" {
  command = plan

  assert {
    condition     = length(wiz_cloud_configuration_rule.this) == length(fileset("${path.module}/../rules", "aws/*/rule.yaml"))
    error_message = "Expected one rule per rule folder."
  }

  assert {
    condition     = wiz_cloud_configuration_rule.this["s3-versioning-enabled"].opa_policy == file("${path.module}/../rules/aws/s3-versioning-enabled/policy.rego")
    error_message = "opa_policy must be the policy.rego contents."
  }

  assert {
    condition     = wiz_cloud_configuration_rule.this["s3-deny-insecure-transport"].name == "Custom - S3 bucket policy denies insecure transport"
    error_message = "name_prefix not applied."
  }

  assert {
    condition     = contains([for t in wiz_cloud_configuration_rule.this["s3-deny-insecure-transport"].tags : "${t.key}=${t.value}"], "nist-800-53=SC-8, SC-8(1)")
    error_message = "NIST tag must list the rule's controls."
  }

  assert {
    condition     = wiz_cloud_configuration_rule.this["kms-cmk-rotation"].function_as_control == false
    error_message = "function_as_control must default to false."
  }
}

run "excludes_rules" {
  command = plan

  variables {
    exclude_rules = ["kms-cmk-rotation"]
  }

  assert {
    condition     = !contains(keys(wiz_cloud_configuration_rule.this), "kms-cmk-rotation")
    error_message = "Excluded rule still present."
  }
}

run "overrides_native_types" {
  command = plan

  variables {
    native_type_overrides = { "s3-versioning-enabled" = ["AWS::S3::Bucket"] }
  }

  assert {
    condition     = wiz_cloud_configuration_rule.this["s3-versioning-enabled"].target_native_types == toset(["AWS::S3::Bucket"])
    error_message = "Override not applied."
  }

  assert {
    condition     = wiz_cloud_configuration_rule.this["s3-server-access-logging"].target_native_types == toset(["bucket"])
    error_message = "Rules without an override must keep their rule.yaml native types."
  }
}

run "rejects_empty_override" {
  command = plan

  variables {
    native_type_overrides = { "s3-versioning-enabled" = [""] }
  }

  expect_failures = [var.native_type_overrides]
}

run "rejects_unknown_override_key" {
  command = plan

  variables {
    native_type_overrides = { "not-a-rule" = ["bucket"] }
  }

  expect_failures = [var.native_type_overrides]
}
