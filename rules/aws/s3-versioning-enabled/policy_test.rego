package wiz_test

import future.keywords.if

import data.wiz

test_enabled_passes if {
	wiz.result == "pass" with input as {"Name": "b", "VersioningConfiguration": {"Status": "Enabled"}}
}

test_camel_case_enabled_passes if {
	wiz.result == "pass" with input as {"name": "b", "versioningConfiguration": {"status": "Enabled"}}
}

test_suspended_fails if {
	wiz.result == "fail" with input as {"Name": "b", "VersioningConfiguration": {"Status": "Suspended"}}
}

test_never_enabled_fails if {
	wiz.result == "fail" with input as {"Name": "b", "VersioningConfiguration": {}}
}

test_config_absent_fails if {
	wiz.result == "fail" with input as {"Name": "b"}
}

test_status_null_fails if {
	wiz.result == "fail" with input as {"Name": "b", "VersioningConfiguration": {"Status": null}}
}

test_directory_bucket_skips if {
	wiz.result == "skip" with input as {"Name": "data--usw2-az1--x-s3"}
}

test_fail_message if {
	wiz.currentConfiguration == "Bucket versioning is Suspended." with input as {"Name": "b", "VersioningConfiguration": {"Status": "Suspended"}}
}

test_fail_message_never_enabled if {
	wiz.currentConfiguration == "Bucket versioning has never been enabled." with input as {"Name": "b"}
}
