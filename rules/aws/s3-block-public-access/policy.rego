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

# S3 directory buckets (name ends in --x-s3) always block public access and have no setting.
directory_bucket if endswith(fieldd(input, "Name", "name", ""), "--x-s3")

pab := fieldd(input, "PublicAccessBlockConfiguration", "publicAccessBlockConfiguration", {})

settings := [
	["BlockPublicAcls", "blockPublicAcls"],
	["IgnorePublicAcls", "ignorePublicAcls"],
	["BlockPublicPolicy", "blockPublicPolicy"],
	["RestrictPublicBuckets", "restrictPublicBuckets"],
]

off := [s[0] | some s in settings; fieldd(pab, s[0], s[1], false) != true]

default result := "pass"

result := "skip" if {
	directory_bucket
} else := "fail" if {
	count(off) > 0
}

currentConfiguration := sprintf("Bucket public access block settings not enabled: %s.", [concat(", ", off)]) if result == "fail"

expectedConfiguration := "All four bucket-level S3 Block Public Access settings are true."
