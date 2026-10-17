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

# S3 directory buckets (name ends in --x-s3) do not support server access logging.
directory_bucket if endswith(fieldd(input, "Name", "name", ""), "--x-s3")

target_bucket := fieldd(fieldd(input, "LoggingEnabled", "loggingEnabled", {}), "TargetBucket", "targetBucket", "")

default result := "pass"

result := "skip" if {
	directory_bucket
} else := "fail" if {
	target_bucket == ""
}

currentConfiguration := "Server access logging is not enabled." if result == "fail"

expectedConfiguration := "Server access logging is enabled with a target bucket."
