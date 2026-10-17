package wiz_test

import future.keywords.if

import data.wiz

provider := "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"

stmt(cond) := {
	"Effect": "Allow",
	"Principal": {"Federated": provider},
	"Action": "sts:AssumeRoleWithWebIdentity",
	"Condition": cond,
}

aud := {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}

role(stmts) := {"RoleName": "deploy", "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": stmts}}

# object.union deep-merges, so a StringEquals sub joins the StringEquals aud instead of replacing it.
pinned(op, sub) := stmt(object.union({"StringEquals": aud}, {op: {"token.actions.githubusercontent.com:sub": sub}}))

test_branch_pinned_passes if {
	wiz.result == "pass" with input as role([pinned("StringEquals", "repo:org/app:ref:refs/heads/main")])
}

test_aud_and_sub_in_one_stringequals_passes if {
	s := stmt({"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": "repo:org/app:environment:prod"}})
	wiz.result == "pass" with input as role([s])
}

test_stringlike_branch_wildcard_passes if {
	wiz.result == "pass" with input as role([pinned("StringLike", "repo:org/app:*")])
}

test_environment_list_passes if {
	wiz.result == "pass" with input as role([pinned("StringLike", ["repo:org/app:environment:prod", "repo:org/app:ref:refs/tags/v*"])])
}

test_single_item_list_same_as_string if {
	wiz.result == "pass" with input as role([pinned("StringEquals", ["repo:org/app:ref:refs/heads/main"])])
}

test_literal_star_under_stringequals_passes if {
	wiz.result == "pass" with input as role([pinned("StringEquals", "repo:org/app:*")])
}

test_govcloud_provider_passes if {
	s := object.union(pinned("StringEquals", "repo:org/app:ref:refs/heads/main"), {"Principal": {"Federated": "arn:aws-us-gov:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"}})
	wiz.result == "pass" with input as role([s])
}

test_url_encoded_passes if {
	doc := {"Version": "2012-10-17", "Statement": [pinned("StringEquals", "repo:org/app:ref:refs/heads/main")]}
	wiz.result == "pass" with input as {"assumeRolePolicyDocument": urlquery.encode(json.marshal(doc))}
}

test_json_string_passes if {
	doc := {"Version": "2012-10-17", "Statement": pinned("StringEquals", "repo:org/app:ref:refs/heads/main")}
	wiz.result == "pass" with input as {"AssumeRolePolicyDocument": json.marshal(doc)}
}

test_foranyvalue_stringlike_passes if {
	wiz.result == "pass" with input as role([pinned("ForAnyValue:StringLike", "repo:org/app:*")])
}

test_org_wildcard_fails if {
	wiz.result == "fail" with input as role([pinned("StringLike", "repo:org/*")])
}

test_org_wildcard_any_ref_fails if {
	wiz.result == "fail" with input as role([pinned("StringLike", "repo:org/*:*")])
}

test_owner_wildcard_fails if {
	wiz.result == "fail" with input as role([pinned("StringLike", "repo:*/app:*")])
}

test_question_mark_in_repo_fails if {
	wiz.result == "fail" with input as role([pinned("StringLike", "repo:org/ap?:*")])
}

test_one_loose_value_fails if {
	wiz.result == "fail" with input as role([pinned("StringLike", ["repo:org/app:*", "repo:org/*"])])
}

test_one_loose_statement_fails if {
	wiz.result == "fail" with input as role([pinned("StringEquals", "repo:org/app:ref:refs/heads/main"), pinned("StringLike", "repo:org/*")])
}

test_sub_missing_fails if {
	wiz.result == "fail" with input as role([stmt({"StringEquals": aud})])
}

test_aud_missing_fails if {
	wiz.result == "fail" with input as role([stmt({"StringEquals": {"token.actions.githubusercontent.com:sub": "repo:org/app:ref:refs/heads/main"}})])
}

test_aud_wrong_fails if {
	wiz.result == "fail" with input as role([stmt({"StringEquals": {"token.actions.githubusercontent.com:aud": "*", "token.actions.githubusercontent.com:sub": "repo:org/app:ref:refs/heads/main"}})])
}

test_aud_stringlike_wildcard_fails if {
	s := stmt({"StringLike": {"token.actions.githubusercontent.com:aud": "*", "token.actions.githubusercontent.com:sub": "repo:org/app:*"}})
	wiz.result == "fail" with input as role([s])
}

test_no_condition_fails if {
	wiz.result == "fail" with input as role([object.remove(stmt({}), ["Condition"])])
}

test_sub_without_repo_prefix_fails if {
	wiz.result == "fail" with input as role([pinned("StringLike", "*")])
}

test_federated_list_relevant if {
	s := object.union(stmt({"StringEquals": aud}), {"Principal": {"Federated": ["arn:aws:iam::1:saml-provider/x", provider]}})
	wiz.result == "fail" with input as role([s])
}

test_action_list_relevant if {
	s := object.union(stmt({"StringEquals": aud}), {"Action": ["sts:TagSession", "sts:AssumeRoleWithWebIdentity"]})
	wiz.result == "fail" with input as role([s])
}

test_non_github_role_skips if {
	wiz.result == "skip" with input as role([{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}])
}

test_deny_statement_ignored_skips if {
	s := object.union(stmt({}), {"Effect": "Deny"})
	wiz.result == "skip" with input as role([s])
}

test_empty_statements_skips if {
	wiz.result == "skip" with input as role([])
}

test_document_absent_skips if {
	wiz.result == "skip" with input as {"RoleName": "deploy"}
}

test_unparseable_fails if {
	wiz.result == "fail" with input as {"AssumeRolePolicyDocument": "%7Bbroken"}
	wiz.currentConfiguration == "Trust policy could not be parsed." with input as {"AssumeRolePolicyDocument": "%7Bbroken"}
}

test_fail_message if {
	wiz.currentConfiguration == "A GitHub OIDC trust statement is not pinned to a specific repository with aud sts.amazonaws.com." with input as role([pinned("StringLike", "repo:org/*")])
}
