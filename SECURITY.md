# Security policy

## Reporting a vulnerability

Please report security problems through GitHub's private vulnerability
reporting ("Report a vulnerability" on the Security tab), not in a public
issue. Include the rule, a sample resource JSON, and the result you expected.

## Scope

In scope: a rule that passes a resource its documentation says it fails, a
way to make a non-compliant resource skip a rule, or a module input that
silently weakens a rule.

Out of scope: differences between the field names in the test fixtures and a
specific Wiz tenant's resource JSON. Those are covered by the first-use check
in the README.
