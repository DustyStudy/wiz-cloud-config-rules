package wiz_test

import future.keywords.if

import data.wiz

test_logging_on_passes if {
	wiz.result == "pass" with input as {"Name": "b", "LoggingEnabled": {"TargetBucket": "logs", "TargetPrefix": "b/"}}
}

test_camel_case_passes if {
	wiz.result == "pass" with input as {"name": "b", "loggingEnabled": {"targetBucket": "logs"}}
}

# PascalCase top level, lowerCamel nested.
test_mixed_case_passes if {
	wiz.result == "pass" with input as {"Name": "b", "LoggingEnabled": {"targetBucket": "logs"}}
}

test_logging_absent_fails if {
	wiz.result == "fail" with input as {"Name": "b"}
}

test_logging_null_fails if {
	wiz.result == "fail" with input as {"Name": "b", "LoggingEnabled": null}
}

test_no_target_bucket_fails if {
	wiz.result == "fail" with input as {"Name": "b", "LoggingEnabled": {"TargetBucket": ""}}
}

test_directory_bucket_skips if {
	wiz.result == "skip" with input as {"Name": "x--use1-az4--x-s3"}
}

test_fail_message if {
	wiz.currentConfiguration == "Server access logging is not enabled." with input as {"Name": "b"}
}
