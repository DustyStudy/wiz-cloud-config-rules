output "rule_ids" {
  description = "Wiz rule ID for each rule, keyed by rule ID."
  value       = { for id, r in wiz_cloud_configuration_rule.this : id => r.id }
}
