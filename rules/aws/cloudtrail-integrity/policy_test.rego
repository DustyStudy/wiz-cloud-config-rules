package wiz_test

import future.keywords.if

import data.wiz

trail := {"Name": "org", "LogFileValidationEnabled": true, "KmsKeyId": "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/abc", "IsMultiRegionTrail": true}

test_compliant_passes if {
	wiz.result == "pass" with input as trail
}

test_camel_case_passes if {
	wiz.result == "pass" with input as {"logFileValidationEnabled": true, "kmsKeyId": "k", "isMultiRegionTrail": true}
}

test_no_validation_fails if {
	wiz.result == "fail" with input as object.union(trail, {"LogFileValidationEnabled": false})
}

test_no_kms_fails if {
	wiz.result == "fail" with input as object.remove(trail, ["KmsKeyId"])
}

test_single_region_fails if {
	wiz.result == "fail" with input as object.union(trail, {"IsMultiRegionTrail": false})
}

test_one_gap_message if {
	wiz.currentConfiguration == "Trail is missing: KMS encryption." with input as object.remove(trail, ["KmsKeyId"])
}

test_all_absent_fails_listing_all if {
	wiz.currentConfiguration == "Trail is missing: log file validation, KMS encryption, multi-region coverage." with input as {"Name": "t"}
}
