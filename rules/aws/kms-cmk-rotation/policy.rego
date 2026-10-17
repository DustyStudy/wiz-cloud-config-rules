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

# Key metadata may be nested (DescribeKey response) or flat on the resource.
meta := fieldd(input, "KeyMetadata", "keyMetadata", input)

attr(pascal, camel) := fieldd(meta, pascal, camel, "")

# Automatic rotation only applies to enabled, customer managed, symmetric keys with KMS-generated material.
eligible if {
	attr("KeyManager", "keyManager") == "CUSTOMER"
	attr("KeyState", "keyState") == "Enabled"
	attr("KeySpec", "keySpec") == "SYMMETRIC_DEFAULT"
	attr("Origin", "origin") == "AWS_KMS"
}

rotation_enabled := fieldd(input, "KeyRotationEnabled", "keyRotationEnabled", false)

# AWS defaults the rotation period to 365 days when rotation is enabled without one.
period := fieldd(input, "RotationPeriodInDays", "rotationPeriodInDays", 365)

default result := "pass"

result := "skip" if {
	not eligible
} else := "fail" if {
	rotation_enabled != true
} else := "fail" if {
	to_number(period) > 365
}

currentConfiguration := "Automatic key rotation is disabled." if {
	result == "fail"
	rotation_enabled != true
} else := sprintf("Key rotation period is %v days.", [period]) if {
	result == "fail"
}

expectedConfiguration := "Automatic key rotation is enabled with a period of 365 days or less."
