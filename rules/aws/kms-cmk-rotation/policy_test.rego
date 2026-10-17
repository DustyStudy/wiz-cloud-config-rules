package wiz_test

import future.keywords.if

import data.wiz

meta := {"KeyManager": "CUSTOMER", "KeyState": "Enabled", "KeySpec": "SYMMETRIC_DEFAULT", "Origin": "AWS_KMS"}

key(extra) := object.union({"KeyMetadata": meta}, extra)

test_rotation_on_default_period_passes if {
	wiz.result == "pass" with input as key({"KeyRotationEnabled": true})
}

test_period_365_passes if {
	wiz.result == "pass" with input as key({"KeyRotationEnabled": true, "RotationPeriodInDays": 365})
}

test_period_90_passes if {
	wiz.result == "pass" with input as key({"KeyRotationEnabled": true, "RotationPeriodInDays": 90})
}

test_period_366_fails if {
	wiz.result == "fail" with input as key({"KeyRotationEnabled": true, "RotationPeriodInDays": 366})
}

test_rotation_off_fails if {
	wiz.result == "fail" with input as key({"KeyRotationEnabled": false})
}

test_rotation_missing_fails if {
	wiz.result == "fail" with input as key({})
}

test_rotation_string_true_fails if {
	wiz.result == "fail" with input as key({"KeyRotationEnabled": "true"})
}

test_flat_camel_case_passes if {
	wiz.result == "pass" with input as {"keyManager": "CUSTOMER", "keyState": "Enabled", "keySpec": "SYMMETRIC_DEFAULT", "origin": "AWS_KMS", "keyRotationEnabled": true}
}

test_aws_managed_skips if {
	wiz.result == "skip" with input as {"KeyMetadata": object.union(meta, {"KeyManager": "AWS"})}
}

test_disabled_key_skips if {
	wiz.result == "skip" with input as {"KeyMetadata": object.union(meta, {"KeyState": "Disabled"})}
}

test_imported_material_skips if {
	wiz.result == "skip" with input as {"KeyMetadata": object.union(meta, {"Origin": "EXTERNAL"})}
}

test_custom_key_store_skips if {
	wiz.result == "skip" with input as {"KeyMetadata": object.union(meta, {"Origin": "AWS_CLOUDHSM"})}
}

test_hmac_skips if {
	wiz.result == "skip" with input as {"KeyMetadata": object.union(meta, {"KeySpec": "HMAC_256"})}
}

test_metadata_missing_skips if {
	wiz.result == "skip" with input as {"KeyRotationEnabled": false}
}

test_fail_message_disabled if {
	wiz.currentConfiguration == "Automatic key rotation is disabled." with input as key({"KeyRotationEnabled": false})
}

test_fail_message_period if {
	wiz.currentConfiguration == "Key rotation period is 366 days." with input as key({"KeyRotationEnabled": true, "RotationPeriodInDays": 366})
}

test_invalid_period_fails if {
	wiz.result == "fail" with input as key({"KeyRotationEnabled": true, "RotationPeriodInDays": "bad"})
}

test_null_period_uses_default if {
	wiz.result == "pass" with input as key({"KeyRotationEnabled": true, "RotationPeriodInDays": null})
}
