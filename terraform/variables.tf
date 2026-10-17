variable "exclude_rules" {
  description = "Rule IDs (folder names under rules/aws) to leave out."
  type        = set(string)
  default     = []
}

variable "scope_account_ids" {
  description = "Wiz cloud account IDs to assess. Null assesses all accounts."
  type        = set(string)
  default     = null
}

variable "function_as_control" {
  description = "Also create Issues, not only Configuration Findings. Turn on after tuning out false positives."
  type        = bool
  default     = false
}

variable "name_prefix" {
  description = "Prefix added to every rule name, to tell these rules apart from built-ins."
  type        = string
  default     = "Custom - "
}

variable "native_type_overrides" {
  description = "Replace a rule's target_native_types, keyed by rule ID. Use when a native type name in rule.yaml does not match your tenant."
  type        = map(list(string))
  default     = {}

  validation {
    condition     = alltrue([for types in values(var.native_type_overrides) : length(types) > 0 && alltrue([for t in types : trimspace(t) != ""])])
    error_message = "Each native_type_overrides entry needs at least one non-empty native type."
  }

  validation {
    condition     = length(setsubtract(keys(var.native_type_overrides), keys(local.all_rules))) == 0
    error_message = "native_type_overrides has keys that are not rule IDs: ${join(", ", setsubtract(keys(var.native_type_overrides), keys(local.all_rules)))}."
  }
}
