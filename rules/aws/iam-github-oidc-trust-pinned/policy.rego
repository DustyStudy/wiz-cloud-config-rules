package wiz

import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# field returns obj[pascal] if present (even false/null), else obj[camel]; undefined if neither.
field(obj, pascal, camel) := v if {
	v := obj[pascal]
} else := v if {
	v := obj[camel]
}

# fieldd is field with a default when neither key exists or the value is null.
fieldd(obj, pascal, camel, d) := v if {
	v := field(obj, pascal, camel)
	v != null
} else := d

# as_list normalizes a single value or a list to a list.
as_list(x) := x if is_array(x)

else := [x]

# policy_raw is the raw document (string or object); undefined when absent, null or empty.
policy_raw := p if {
	p := field(input, "AssumeRolePolicyDocument", "assumeRolePolicyDocument")
	p != null
	p != ""
}

# IAM-style APIs return URL-encoded documents; plain JSON starts with "{".
decoded_text(s) := s if startswith(s, "{")

else := urlquery.decode(s)

policy_doc := d if {
	is_object(policy_raw)
	d := policy_raw
} else := d if {
	is_string(policy_raw)
	t := decoded_text(policy_raw)
	json.is_valid(t)
	d := json.unmarshal(t)
}

policy_unparseable if {
	policy_raw
	not policy_doc
}

statements := [s | some s in as_list(object.get(policy_doc, "Statement", []))]

gh := "token.actions.githubusercontent.com"

aud_key := sprintf("%s:aud", [gh])

sub_key := sprintf("%s:sub", [gh])

assume_action(a) if {
	some v in as_list(a)

	# IAM action names are case-insensitive and may use * and ? wildcards.
	glob.match(lower(v), [], "sts:assumerolewithwebidentity")
}

# Matches the GitHub OIDC provider ARN in any partition.
github_principal(p) if {
	is_object(p)
	some f in as_list(object.get(p, "Federated", []))
	endswith(f, sprintf(":oidc-provider/%s", [gh]))
}

relevant contains s if {
	some s in statements
	object.get(s, "Effect", "") == "Allow"
	assume_action(object.get(s, "Action", []))
	github_principal(object.get(s, "Principal", {}))
}

# base_op strips the ForAnyValue: prefix. ForAllValues: is kept, so it never counts as pinning:
# it matches when the claim is absent.
base_op(op) := trim_prefix(op, "ForAnyValue:")

# pairs lists [operator, value] for every value of key k in a condition block.
pairs(cond, k) := [[base_op(op), v] |
	some op, kv in cond
	is_object(kv)
	some v in as_list(object.get(kv, k, []))
]

aud_ok(cond) if {
	vals := [p[1] | some p in pairs(cond, aud_key); p[0] == "StringEquals"]
	count(vals) > 0
	every v in vals {
		v == "sts.amazonaws.com"
	}
}

# repo_part returns "<owner>/<repo>" from "repo:<owner>/<repo>[:...]".
repo_part(v) := split(trim_prefix(v, "repo:"), ":")[0] if startswith(v, "repo:")

concrete_repo(r) if {
	parts := split(r, "/")
	count(parts) == 2
	parts[0] != ""
	parts[1] != ""
}

# Under StringEquals, * and ? are literal and cannot widen access.
safe_sub(op, v) if {
	op == "StringEquals"
	concrete_repo(repo_part(v))
}

safe_sub(op, v) if {
	op == "StringLike"
	r := repo_part(v)
	concrete_repo(r)
	not contains(r, "*")
	not contains(r, "?")
}

# Values of one key are OR'd, so every sub value must be safe.
sub_ok(cond) if {
	subs := [p | some p in pairs(cond, sub_key); p[0] in {"StringEquals", "StringLike"}]
	count(subs) > 0
	every p in subs {
		safe_sub(p[0], p[1])
	}
}

pinned(s) if {
	cond := object.get(s, "Condition", {})
	aud_ok(cond)
	sub_ok(cond)
}

loose contains s if {
	some s in relevant
	not pinned(s)
}

default result := "pass"

result := "fail" if {
	policy_unparseable
} else := "skip" if {
	count(relevant) == 0
} else := "fail" if {
	count(loose) > 0
}

currentConfiguration := "Trust policy could not be parsed." if {
	result == "fail"
	policy_unparseable
} else := "A GitHub OIDC trust statement is not pinned to a specific repository with aud sts.amazonaws.com." if {
	result == "fail"
}

expectedConfiguration := "Every statement trusting token.actions.githubusercontent.com requires aud sts.amazonaws.com and a sub naming a concrete owner/repository (wildcards only after the repository)."
