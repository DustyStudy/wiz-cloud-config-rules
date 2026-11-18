package wiz

import future.keywords.if
import future.keywords.in

# field returns obj[pascal] if present (even false/null), else obj[camel]; undefined if neither.
field(obj, pascal, camel) := v if {
	v := obj[pascal]
} else := v if {
	v := obj[camel]
}

# fieldd is field with a default when neither key exists or the value is null.
fieldd(obj, pascal, camel, d) := v if {
	v := field(obj, pascal, camel)
	v != null
} else := d

# Guidance, not a FedRAMP parameter: OMB M-21-31 asks for 12 months of active storage.
# Change this to the retention your AU-11 decision sets.
min_retention_days := 365

# CloudWatch omits retentionInDays when logs never expire, which keeps everything.
retention := fieldd(input, "RetentionInDays", "retentionInDays", 0)

short_retention if {
	retention != 0
	retention < min_retention_days
}

short_retention if not is_number(retention)

has_key if fieldd(input, "KmsKeyId", "kmsKeyId", "") != ""

gaps := array.concat(
	[g | short_retention; g := sprintf("retention of at least %d days (is %v)", [min_retention_days, retention])],
	[g | not has_key; g := "KMS encryption"],
)

default result := "pass"

result := "fail" if count(gaps) > 0

currentConfiguration := sprintf("Log group is missing: %s.", [concat(", ", gaps)]) if result == "fail"

expectedConfiguration := sprintf("Log group is encrypted with a KMS key and keeps logs for at least %d days.", [min_retention_days])
