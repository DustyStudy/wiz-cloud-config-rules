package wiz_test

import future.keywords.if

import data.wiz

good := {
	"Effect": "Deny", "Principal": "*", "Action": "s3:*",
	"Resource": ["arn:aws:s3:::b", "arn:aws:s3:::b/*"],
	"Condition": {"Bool": {"aws:SecureTransport": "false"}},
}

pol(stmts) := {"Version": "2012-10-17", "Statement": stmts}

# with_cond replaces the whole Condition block (object.union would merge nested keys).
with_cond(c) := object.union(object.remove(good, ["Condition"]), {"Condition": c})

test_object_policy_passes if {
	wiz.result == "pass" with input as {"Name": "b", "Policy": pol([good])}
}

test_json_string_policy_passes if {
	wiz.result == "pass" with input as {"name": "b", "policy": json.marshal(pol([good]))}
}

test_url_encoded_policy_passes if {
	wiz.result == "pass" with input as {"Name": "b", "Policy": urlquery.encode(json.marshal(pol([good])))}
}

test_single_statement_object_passes if {
	wiz.result == "pass" with input as {"Name": "b", "Policy": {"Statement": good}}
}

test_govcloud_arns_pass if {
	s := object.union(good, {"Resource": ["arn:aws-us-gov:s3:::b", "arn:aws-us-gov:s3:::b/*"]})
	wiz.result == "pass" with input as {"Name": "b", "Policy": pol([s])}
}

test_resource_star_and_principal_aws_star_pass if {
	s := object.union(good, {"Resource": "*", "Principal": {"AWS": "*"}, "Action": ["*"]})
	wiz.result == "pass" with input as {"Name": "b", "Policy": pol([s])}
}

test_tls_version_condition_passes if {
	s := with_cond({"NumericLessThan": {"s3:TlsVersion": "1.2"}})
	wiz.result == "pass" with input as {"Name": "b", "Policy": pol([s])}
}

test_bool_if_exists_passes if {
	s := with_cond({"BoolIfExists": {"aws:SecureTransport": false}})
	wiz.result == "pass" with input as {"Name": "b", "Policy": pol([s])}
}

test_compliant_among_other_statements_passes if {
	other := {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"}, "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}
	wiz.result == "pass" with input as {"Name": "b", "Policy": pol([other, good])}
}

test_policy_absent_fails if {
	wiz.result == "fail" with input as {"Name": "b"}
}

test_policy_null_fails if {
	wiz.result == "fail" with input as {"Name": "b", "Policy": null}
}

test_policy_absent_message if {
	wiz.currentConfiguration == "Bucket policy is missing." with input as {"Name": "b"}
}

test_malformed_policy_fails_with_message if {
	wiz.result == "fail" with input as {"Name": "b", "Policy": "{not json"}
	wiz.currentConfiguration == "Bucket policy could not be parsed." with input as {"Name": "b", "Policy": "{not json"}
}

test_empty_statement_list_fails if {
	wiz.result == "fail" with input as {"Name": "b", "Policy": pol([])}
}

test_allow_only_fails if {
	s := object.union(good, {"Effect": "Allow"})
	wiz.result == "fail" with input as {"Name": "b", "Policy": pol([s])}
}

test_single_principal_fails if {
	s := object.union(good, {"Principal": {"AWS": "arn:aws:iam::111122223333:root"}})
	wiz.result == "fail" with input as {"Name": "b", "Policy": pol([s])}
}

test_objects_only_fails if {
	s := object.union(good, {"Resource": "arn:aws:s3:::b/*"})
	wiz.result == "fail" with input as {"Name": "b", "Policy": pol([s])}
}

test_other_bucket_fails if {
	s := object.union(good, {"Resource": ["arn:aws:s3:::other", "arn:aws:s3:::other/*"]})
	wiz.result == "fail" with input as {"Name": "b", "Policy": pol([s])}
}

test_bucket_name_suffix_does_not_match if {
	s := object.union(good, {"Resource": ["arn:aws:s3:::xb", "arn:aws:s3:::xb/*"]})
	wiz.result == "fail" with input as {"Name": "b", "Policy": pol([s])}
}

test_limited_action_fails if {
	s := object.union(good, {"Action": "s3:GetObject"})
	wiz.result == "fail" with input as {"Name": "b", "Policy": pol([s])}
}

test_extra_condition_fails if {
	s := with_cond({"Bool": {"aws:SecureTransport": "false"}, "StringEquals": {"aws:PrincipalAccount": "111122223333"}})
	wiz.result == "fail" with input as {"Name": "b", "Policy": pol([s])}
}

test_tls_version_too_low_fails if {
	s := with_cond({"NumericLessThan": {"s3:TlsVersion": "1.0"}})
	wiz.result == "fail" with input as {"Name": "b", "Policy": pol([s])}
}

test_secure_transport_true_fails if {
	s := with_cond({"Bool": {"aws:SecureTransport": "true"}})
	wiz.result == "fail" with input as {"Name": "b", "Policy": pol([s])}
}

test_generic_fail_message if {
	s := object.union(good, {"Effect": "Allow"})
	wiz.currentConfiguration == "Bucket policy has no statement denying all principals and all S3 actions on the bucket and its objects when aws:SecureTransport is false." with input as {"Name": "b", "Policy": pol([s])}
}

test_all_buckets_arn_wildcard_passes if {
	s := object.union(good, {"Resource": "arn:aws:s3:::*"})
	wiz.result == "pass" with input as {"Name": "b", "Policy": pol([s])}
}
