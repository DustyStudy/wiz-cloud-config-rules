package wiz_test

import future.keywords.if

import data.wiz

db := {"DBInstanceIdentifier": "app", "StorageEncrypted": true, "KmsKeyId": "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/abc", "PubliclyAccessible": false}

test_compliant_passes if {
	wiz.result == "pass" with input as db
}

test_camel_case_passes if {
	wiz.result == "pass" with input as {"storageEncrypted": true, "kmsKeyId": "k", "publiclyAccessible": false}
}

test_unencrypted_fails if {
	wiz.result == "fail" with input as object.union(db, {"StorageEncrypted": false})
}

test_no_key_fails if {
	wiz.currentConfiguration == "DB instance is missing: a KMS key." with input as object.remove(db, ["KmsKeyId"])
}

test_public_fails if {
	wiz.currentConfiguration == "DB instance is missing: PubliclyAccessible set to false." with input as object.union(db, {"PubliclyAccessible": true})
}

test_public_absent_fails if {
	wiz.result == "fail" with input as object.remove(db, ["PubliclyAccessible"])
}

test_public_null_fails if {
	wiz.result == "fail" with input as object.union(db, {"PubliclyAccessible": null})
}

test_all_absent_fails_listing_all if {
	wiz.currentConfiguration == "DB instance is missing: storage encryption, a KMS key, PubliclyAccessible set to false." with input as {"DBInstanceIdentifier": "app"}
}
