#!/usr/bin/env bash
# Runs every Rego gate. Each rule folder is checked alone: all rules are `package wiz`.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! opa fmt --fail --list rules >/dev/null; then
  echo "opa fmt: these files need formatting:" >&2
  opa fmt --list rules >&2
  exit 1
fi

coverage=$(mktemp)
trap 'rm -f "${coverage}"' EXIT

status=0
for dir in rules/aws/*/; do
  echo "== ${dir}"
  opa check --strict "${dir}" || status=1
  opa check --v0-compatible "${dir}" || status=1
  if ! opa test --coverage --threshold 90 "${dir}" > "${coverage}"; then
    opa test -v "${dir}" || true
    echo "coverage: $(jq -r .coverage "${coverage}" 2>/dev/null)%" >&2
    status=1
  fi
done
exit "${status}"
