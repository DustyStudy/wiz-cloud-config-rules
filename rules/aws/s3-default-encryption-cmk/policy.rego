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

kms_algorithms := {"aws:kms", "aws:kms:dsse"}

defaults := [d |
	some r in fieldd(fieldd(input, "ServerSideEncryptionConfiguration", "serverSideEncryptionConfiguration", {}), "Rules", "rules", [])
	d := fieldd(r, "ApplyServerSideEncryptionByDefault", "applyServerSideEncryptionByDefault", {})
]

algorithm := fieldd(defaults[0], "SSEAlgorithm", "sseAlgorithm", "") if count(defaults) > 0

else := ""

key_id := fieldd(defaults[0], "KMSMasterKeyID", "kmsMasterKeyID", "") if count(defaults) > 0

else := ""

aws_managed_key if key_id == "alias/aws/s3"

aws_managed_key if endswith(key_id, ":alias/aws/s3")

default result := "pass"

result := "fail" if {
	not algorithm in kms_algorithms
} else := "fail" if {
	key_id == ""
} else := "fail" if {
	aws_managed_key
}

currentConfiguration := "Default encryption is not configured." if {
	result == "fail"
	algorithm == ""
} else := sprintf("Default encryption is %s, not SSE-KMS with a customer managed key.", [algorithm]) if {
	result == "fail"
	not algorithm in kms_algorithms
} else := "Default encryption uses SSE-KMS without a key ID (AWS managed key)." if {
	result == "fail"
	key_id == ""
} else := "Default encryption uses the AWS managed key aws/s3." if {
	result == "fail"
}

expectedConfiguration := "Default encryption is SSE-KMS or DSSE-KMS with a customer managed KMS key."
