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

opts := fieldd(input, "MetadataOptions", "metadataOptions", {})

tokens := fieldd(opts, "HttpTokens", "httpTokens", "")

# AWS defaults the metadata endpoint to enabled.
endpoint := fieldd(opts, "HttpEndpoint", "httpEndpoint", "enabled")

default result := "pass"

result := "fail" if {
	endpoint != "disabled"
	tokens != "required"
}

currentConfiguration := "IMDS HttpTokens is not set." if {
	result == "fail"
	tokens == ""
} else := sprintf("IMDS HttpTokens is %s.", [tokens]) if {
	result == "fail"
}

expectedConfiguration := "IMDSv2 is required (HttpTokens is required) or the metadata endpoint is disabled."
