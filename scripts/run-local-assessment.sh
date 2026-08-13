#!/bin/sh
# Project 25: evidence collection only. Findings do not block this baseline run.
set +e

results_dir="${1:-scan-results}"
evidence_dir="${2:-/opt/project25/evidence/generated}"

mkdir -p "$results_dir" "$evidence_dir"

gitleaks detect --source . --no-git --redact --report-format json \
  --report-path "$results_dir/E004-gitleaks.json"
gitleaks_status=$?

bandit --recursive demo-app --format json --output "$results_dir/E005-bandit.json"
bandit_status=$?

pip-audit --requirement demo-app/requirements.txt --format json \
  --output "$results_dir/E006-pip-audit.json"
audit_status=$?

# Some tools do not emit a result file when they fail before analysis.
test -f "$results_dir/E004-gitleaks.json" || printf '[]\n' > "$results_dir/E004-gitleaks.json"
test -f "$results_dir/E005-bandit.json" || printf '{"results": []}\n' > "$results_dir/E005-bandit.json"
test -f "$results_dir/E006-pip-audit.json" || printf '[]\n' > "$results_dir/E006-pip-audit.json"

printf '{"gitleaks_exit_code": %s, "bandit_exit_code": %s, "pip_audit_exit_code": %s}\n' \
  "$gitleaks_status" "$bandit_status" "$audit_status" > "$results_dir/E007-scan-exit-codes.json"

cp "$results_dir"/* "$evidence_dir"/

# Intentionally return success: this is an evidence collection baseline, not a policy gate.
exit 0
