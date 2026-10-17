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

# as_list normalizes a single value or a list to a list.
as_list(x) := x if is_array(x)

else := [x]

# IAM-style APIs return URL-encoded documents; plain JSON starts with "{".
decoded_text(s) := s if startswith(s, "{")

else := urlquery.decode(s)

policy_raw := field(input, "Policy", "policy")

policy_doc := d if {
	is_object(policy_raw)
	d := policy_raw
} else := d if {
	is_string(policy_raw)
	t := decoded_text(policy_raw)
	json.is_valid(t)
	d := json.unmarshal(t)
}

# Server access log destinations only support SSE-S3, so a bucket that lets the
# logging service write to it is out of scope.
log_destination if {
	some s in as_list(object.get(policy_doc, "Statement", []))
	object.get(s, "Effect", "") == "Allow"
	some svc in as_list(object.get(object.get(s, "Principal", {}), "Service", []))
	svc == "logging.s3.amazonaws.com"
	some a in as_list(object.get(s, "Action", []))
	glob.match(lower(a), [], "s3:putobject")
	some r in as_list(object.get(s, "Resource", []))
	writes_objects(r)
}

writes_objects("*")

writes_objects(r) if contains(r, sprintf(":::%s/", [fieldd(input, "Name", "name", "")]))

# S3 directory buckets (name ends in --x-s3) are not general purpose buckets.
directory_bucket if endswith(fieldd(input, "Name", "name", ""), "--x-s3")

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

result := "skip" if {
	directory_bucket
} else := "skip" if {
	log_destination
} else := "fail" if {
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
