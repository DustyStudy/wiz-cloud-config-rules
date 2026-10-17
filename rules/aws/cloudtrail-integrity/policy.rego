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

validation_on if fieldd(input, "LogFileValidationEnabled", "logFileValidationEnabled", false) == true

kms_on if fieldd(input, "KmsKeyId", "kmsKeyId", "") != ""

multi_region if fieldd(input, "IsMultiRegionTrail", "isMultiRegionTrail", false) == true

gaps := array.concat(
	array.concat(
		[g | not validation_on; g := "log file validation"],
		[g | not kms_on; g := "KMS encryption"],
	),
	[g | not multi_region; g := "multi-region coverage"],
)

default result := "pass"

result := "fail" if count(gaps) > 0

currentConfiguration := sprintf("Trail is missing: %s.", [concat(", ", gaps)]) if result == "fail"

expectedConfiguration := "Trail has log file validation, KMS encryption with a customer managed key, and multi-region coverage."
