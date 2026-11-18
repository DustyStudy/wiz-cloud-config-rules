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

encrypted if fieldd(input, "StorageEncrypted", "storageEncrypted", false) == true

has_key if fieldd(input, "KmsKeyId", "kmsKeyId", "") != ""

# Missing PubliclyAccessible is treated as public so absent data fails.
private if fieldd(input, "PubliclyAccessible", "publiclyAccessible", true) == false

gaps := array.concat(
	array.concat(
		[g | not encrypted; g := "storage encryption"],
		[g | not has_key; g := "a KMS key"],
	),
	[g | not private; g := "PubliclyAccessible set to false"],
)

default result := "pass"

result := "fail" if count(gaps) > 0

currentConfiguration := sprintf("DB instance is missing: %s.", [concat(", ", gaps)]) if result == "fail"

expectedConfiguration := "DB instance storage is encrypted with a KMS key and the instance is not publicly accessible."
