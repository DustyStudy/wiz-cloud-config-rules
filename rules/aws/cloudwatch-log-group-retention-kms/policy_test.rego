package wiz_test

import future.keywords.if

import data.wiz

lg := {"logGroupName": "/app", "retentionInDays": 400, "kmsKeyId": "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/abc"}

test_compliant_passes if {
	wiz.result == "pass" with input as lg
}

test_pascal_case_passes if {
	wiz.result == "pass" with input as {"RetentionInDays": 365, "KmsKeyId": "k"}
}

test_never_expire_passes if {
	wiz.result == "pass" with input as object.remove(lg, ["retentionInDays"])
}

test_short_retention_fails if {
	wiz.currentConfiguration == "Log group is missing: retention of at least 365 days (is 90)." with input as object.union(lg, {"retentionInDays": 90})
}

test_non_number_retention_fails if {
	wiz.result == "fail" with input as object.union(lg, {"retentionInDays": "400"})
}

test_no_key_fails if {
	wiz.currentConfiguration == "Log group is missing: KMS encryption." with input as object.remove(lg, ["kmsKeyId"])
}

test_both_gaps_listed if {
	wiz.currentConfiguration == "Log group is missing: retention of at least 365 days (is 1), KMS encryption." with input as {"logGroupName": "/app", "retentionInDays": 1}
}
