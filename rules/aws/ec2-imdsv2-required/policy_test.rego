package wiz_test

import future.keywords.if

import data.wiz

test_required_passes if {
	wiz.result == "pass" with input as {"InstanceId": "i-1", "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"}}
}

test_endpoint_disabled_passes if {
	wiz.result == "pass" with input as {"InstanceId": "i-1", "MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "disabled"}}
}

test_optional_fails if {
	wiz.result == "fail" with input as {"InstanceId": "i-1", "MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "enabled"}}
}

test_tokens_missing_fails if {
	wiz.result == "fail" with input as {"InstanceId": "i-1", "MetadataOptions": {"HttpEndpoint": "enabled"}}
}

test_options_absent_fails if {
	wiz.result == "fail" with input as {"InstanceId": "i-1"}
}

test_camel_case_passes if {
	wiz.result == "pass" with input as {"metadataOptions": {"httpTokens": "required"}}
}

test_fail_message if {
	wiz.currentConfiguration == "IMDS HttpTokens is optional." with input as {"MetadataOptions": {"HttpTokens": "optional"}}
}

test_fail_message_not_set if {
	wiz.currentConfiguration == "IMDS HttpTokens is not set." with input as {"InstanceId": "i-1"}
}
