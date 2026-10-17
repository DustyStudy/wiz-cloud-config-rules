package wiz_test

import future.keywords.if

import data.wiz

enc(alg, key) := {"Name": "b", "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": alg, "KMSMasterKeyID": key}}]}}

test_cmk_arn_passes if {
	wiz.result == "pass" with input as enc("aws:kms", "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
}

test_govcloud_cmk_passes if {
	wiz.result == "pass" with input as enc("aws:kms", "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")
}

test_dsse_with_cmk_passes if {
	wiz.result == "pass" with input as enc("aws:kms:dsse", "1234abcd-12ab-34cd-56ef-1234567890ab")
}

test_sse_s3_fails if {
	wiz.result == "fail" with input as enc("AES256", "")
}

test_kms_without_key_fails if {
	wiz.result == "fail" with input as {"Name": "b", "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}}
}

test_aws_managed_alias_fails if {
	wiz.result == "fail" with input as enc("aws:kms", "alias/aws/s3")
}

test_aws_managed_alias_arn_govcloud_fails if {
	wiz.result == "fail" with input as enc("aws:kms", "arn:aws-us-gov:kms:us-gov-west-1:111122223333:alias/aws/s3")
}

test_encryption_absent_fails if {
	wiz.result == "fail" with input as {"Name": "b"}
}

test_empty_rules_fails if {
	wiz.result == "fail" with input as {"Name": "b", "ServerSideEncryptionConfiguration": {"Rules": []}}
}

test_camel_case_passes if {
	wiz.result == "pass" with input as {"name": "b", "serverSideEncryptionConfiguration": {"rules": [{"applyServerSideEncryptionByDefault": {"sseAlgorithm": "aws:kms", "kmsMasterKeyID": "1234abcd-12ab-34cd-56ef-1234567890ab"}}]}}
}

test_fail_message_not_configured if {
	wiz.currentConfiguration == "Default encryption is not configured." with input as {"Name": "b"}
}

test_fail_message_sse_s3 if {
	wiz.currentConfiguration == "Default encryption is AES256, not SSE-KMS with a customer managed key." with input as enc("AES256", "")
}

test_fail_message_no_key if {
	wiz.currentConfiguration == "Default encryption uses SSE-KMS without a key ID (AWS managed key)." with input as enc("aws:kms", "")
}

test_fail_message_aws_managed if {
	wiz.currentConfiguration == "Default encryption uses the AWS managed key aws/s3." with input as enc("aws:kms", "alias/aws/s3")
}
