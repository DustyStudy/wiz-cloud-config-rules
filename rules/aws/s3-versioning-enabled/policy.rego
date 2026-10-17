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

# S3 directory buckets (name ends in --x-s3) do not support versioning.
directory_bucket if endswith(fieldd(input, "Name", "name", ""), "--x-s3")

status := fieldd(fieldd(input, "VersioningConfiguration", "versioningConfiguration", {}), "Status", "status", "")

default result := "pass"

result := "skip" if {
	directory_bucket
} else := "fail" if {
	status != "Enabled"
}

currentConfiguration := "Bucket versioning has never been enabled." if {
	result == "fail"
	status == ""
} else := sprintf("Bucket versioning is %s.", [status]) if {
	result == "fail"
}

expectedConfiguration := "Bucket versioning status is Enabled."
