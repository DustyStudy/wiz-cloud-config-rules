terraform {
  required_version = ">= 1.9"

  required_providers {
    wiz = {
      source  = "tf.app.wiz.io/wizsec/wiz"
      version = ">= 1.28"
    }
  }
}

# Credentials come from the WIZ_CLIENT_ID and WIZ_CLIENT_SECRET environment variables.
provider "wiz" {
  # environment = "gov" # or "fedramp" for Wiz for Gov tenants
}

module "wiz_rules" {
  source = "../../terraform"

  # Pilot on a few accounts first, then remove to assess all accounts.
  # scope_account_ids = ["<wiz-cloud-account-id>"]
}

output "rule_ids" {
  description = "Wiz rule ID for each rule, keyed by rule ID."
  value       = module.wiz_rules.rule_ids
}
