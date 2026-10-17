locals {
  rules_dir  = "${path.module}/../rules"
  rule_files = fileset(local.rules_dir, "aws/*/rule.yaml")

  # fileset returns paths relative to rules_dir, so re-prefix them before reading.
  all_rules = {
    for f in local.rule_files :
    basename(dirname(f)) => merge(yamldecode(file("${local.rules_dir}/${f}")), {
      folder = basename(dirname(f))
      policy = file("${local.rules_dir}/${dirname(f)}/policy.rego")
    })
  }

  rules = { for id, r in local.all_rules : id => r if !contains(var.exclude_rules, id) }

  severities = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
}

# Variable validation cannot see the rule list on Terraform 1.9, so unknown override keys are caught here.
resource "terraform_data" "override_keys" {
  lifecycle {
    precondition {
      condition     = length(setsubtract(keys(var.native_type_overrides), keys(local.all_rules))) == 0
      error_message = "native_type_overrides has keys that are not rule IDs: ${join(", ", setsubtract(keys(var.native_type_overrides), keys(local.all_rules)))}."
    }
  }
}

resource "wiz_cloud_configuration_rule" "this" {
  for_each = local.rules

  name                     = "${var.name_prefix}${each.value.name}"
  description              = each.value.description
  severity                 = each.value.severity
  opa_policy               = each.value.policy
  target_native_types      = lookup(var.native_type_overrides, each.key, each.value.target_native_types)
  remediation_instructions = each.value.remediation
  function_as_control      = var.function_as_control
  scope_account_ids        = var.scope_account_ids

  tags {
    key   = "source"
    value = "wiz-cloud-config-rules"
  }

  tags {
    key   = "rule_id"
    value = each.key
  }

  # One tag for all controls: whether the Wiz API accepts repeated tag keys is unverified.
  tags {
    key   = "nist-800-53"
    value = join(", ", each.value.nist_800_53)
  }

  lifecycle {
    precondition {
      condition     = each.value.id == each.value.folder
      error_message = "rule.yaml id '${each.value.id}' does not match its folder '${each.value.folder}'."
    }
    precondition {
      condition     = contains(local.severities, each.value.severity)
      error_message = "Rule ${each.key} has invalid severity '${each.value.severity}'."
    }
    precondition {
      condition     = length(lookup(var.native_type_overrides, each.key, each.value.target_native_types)) > 0
      error_message = "Rule ${each.key} has no target_native_types."
    }
  }
}
