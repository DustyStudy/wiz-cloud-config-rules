package wiz_test

import future.keywords.if

import data.wiz

test_encrypted_passes if {
	wiz.result == "pass" with input as {"VolumeId": "vol-1", "Encrypted": true, "KmsKeyId": "arn:aws-us-gov:kms:us-gov-east-1:111122223333:key/abc"}
}

test_camel_case_passes if {
	wiz.result == "pass" with input as {"volumeId": "vol-1", "encrypted": true}
}

test_unencrypted_fails if {
	wiz.result == "fail" with input as {"VolumeId": "vol-1", "Encrypted": false}
	wiz.currentConfiguration == "EBS volume is not encrypted." with input as {"VolumeId": "vol-1", "Encrypted": false}
}

test_absent_fails if {
	wiz.result == "fail" with input as {"VolumeId": "vol-1"}
}

test_null_fails if {
	wiz.result == "fail" with input as {"VolumeId": "vol-1", "Encrypted": null}
}

test_string_true_fails if {
	wiz.result == "fail" with input as {"VolumeId": "vol-1", "Encrypted": "true"}
}
