package wiz_test

import future.keywords.if

import data.wiz

all_on := {"BlockPublicAcls": true, "IgnorePublicAcls": true, "BlockPublicPolicy": true, "RestrictPublicBuckets": true}

bucket := {"Name": "data", "PublicAccessBlockConfiguration": all_on}

test_all_on_passes if {
	wiz.result == "pass" with input as bucket
}

test_camel_case_passes if {
	wiz.result == "pass" with input as {"name": "data", "publicAccessBlockConfiguration": {"blockPublicAcls": true, "ignorePublicAcls": true, "blockPublicPolicy": true, "restrictPublicBuckets": true}}
}

test_one_off_fails_naming_it if {
	cfg := object.union(bucket, {"PublicAccessBlockConfiguration": object.union(all_on, {"BlockPublicPolicy": false})})
	wiz.result == "fail" with input as cfg
	wiz.currentConfiguration == "Bucket public access block settings not enabled: BlockPublicPolicy." with input as cfg
}

test_setting_absent_fails if {
	# object.union merges nested objects, so build the input directly.
	wiz.result == "fail" with input as {"Name": "data", "PublicAccessBlockConfiguration": object.remove(all_on, ["RestrictPublicBuckets"])}
}

test_string_true_fails if {
	wiz.result == "fail" with input as object.union(bucket, {"PublicAccessBlockConfiguration": object.union(all_on, {"IgnorePublicAcls": "true"})})
}

test_config_absent_fails_listing_all if {
	wiz.currentConfiguration == "Bucket public access block settings not enabled: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets." with input as {"Name": "data"}
}

test_config_null_fails if {
	wiz.result == "fail" with input as {"Name": "data", "PublicAccessBlockConfiguration": null}
}

test_directory_bucket_skips if {
	wiz.result == "skip" with input as {"Name": "fast--usw2-az1--x-s3"}
}
