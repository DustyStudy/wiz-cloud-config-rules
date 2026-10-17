package wiz

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
	p := field(input, "Policy", "policy")
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

bucket := fieldd(input, "Name", "name", "")

all_principals(p) if p == "*"

all_principals(p) if {
	is_object(p)
	some v in as_list(object.get(p, "AWS", []))
	v == "*"
}

# IAM action names and condition keys are case-insensitive.
all_actions(a) if {
	some v in as_list(a)
	lower(v) in {"*", "s3:*"}
}

# covers is true when a Resource entry matches target ("<bucket>" or "<bucket>/*") in any partition.
covers(resources, _) if {
	some r in as_list(resources)
	r == "*"
}

covers(resources, target) if {
	some r in as_list(resources)
	parts := split(r, ":")
	count(parts) == 6
	parts[0] == "arn"
	parts[2] == "s3"
	parts[5] in {target, "*"}
}

false_value(v) if v == false

false_value(v) if v == "false"

# cond_values lists the values of condition key k (lower case) under operator op.
cond_values(c, op, k) := [v |
	some key, vals in object.get(c, op, {})
	lower(key) == k
	some v in as_list(vals)
]

# The condition block must hold only the transport check; extra conditions narrow the denial.
transport_condition(c) if {
	count(c) == 1
	some op in ["Bool", "BoolIfExists"]
	count(object.get(c, op, {})) == 1
	some v in cond_values(c, op, "aws:securetransport")
	false_value(v)
}

# Plain HTTP requests carry no s3:TlsVersion, so only the IfExists form denies them.
transport_condition(c) if {
	count(c) == 1
	count(object.get(c, "NumericLessThanIfExists", {})) == 1
	some v in cond_values(c, "NumericLessThanIfExists", "s3:tlsversion")
	to_number(v) >= 1.2
}

denies_insecure(s) if {
	object.get(s, "Effect", "") == "Deny"
	all_principals(object.get(s, "Principal", ""))
	all_actions(object.get(s, "Action", []))
	transport_condition(object.get(s, "Condition", {}))
}

# The bucket and its objects may be covered by separate statements.
covered(target) if {
	some s in statements
	denies_insecure(s)
	covers(object.get(s, "Resource", []), target)
}

has_compliant if {
	covered(bucket)
	covered(sprintf("%s/*", [bucket]))
}

# S3 directory buckets (name ends in --x-s3) take s3express actions, which an s3:* denial does not match.
directory_bucket if endswith(bucket, "--x-s3")

default result := "pass"

result := "skip" if {
	directory_bucket
} else := "fail" if {
	not has_compliant
}

currentConfiguration := "Bucket policy is missing." if {
	result == "fail"
	not policy_raw
} else := "Bucket policy could not be parsed." if {
	result == "fail"
	policy_unparseable
} else := "Bucket policy has no statement denying all principals and all S3 actions on the bucket and its objects when aws:SecureTransport is false." if {
	result == "fail"
}

expectedConfiguration := "Bucket policy denies s3:* for all principals on the bucket and its objects when aws:SecureTransport is false (or, with NumericLessThanIfExists, s3:TlsVersion is below 1.2), with no other conditions."
