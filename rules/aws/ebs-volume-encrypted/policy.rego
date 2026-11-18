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

encrypted if fieldd(input, "Encrypted", "encrypted", false) == true

default result := "pass"

result := "fail" if not encrypted

currentConfiguration := "EBS volume is not encrypted." if result == "fail"

expectedConfiguration := "EBS volume is encrypted with a KMS key."
