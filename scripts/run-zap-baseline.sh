#!/bin/sh
# Project 25: passive, local-only DAST baseline. No active attack scan is run.
set +e

results_dir="${1:-dast-results}"
evidence_dir="${2:-/opt/project25/evidence/generated}"
workspace="${3:?Jenkins workspace path is required}"
target_url="${PROJECT25_DAST_TARGET:-http://demo-app:5000}"
docker_network="${PROJECT25_DOCKER_NETWORK:-project25-devsecops-lab_default}"

mkdir -p "$results_dir" "$evidence_dir"

# The Docker daemon needs a Docker-visible volume; --volumes-from shares this
# Jenkins container's persistent workspace with ZAP for report generation.
docker run --rm \
  --network "$docker_network" \
  --volumes-from "$(hostname)" \
  --user root \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t "$target_url" -m 1 -I \
  -J "$workspace/$results_dir/E011-zap-baseline.json" \
  -r "$workspace/$results_dir/E012-zap-baseline.html"
zap_status=$?

test -f "$results_dir/E011-zap-baseline.json" || printf '{"site": [], "alerts": []}\n' > "$results_dir/E011-zap-baseline.json"
test -f "$results_dir/E012-zap-baseline.html" || printf '<!doctype html><title>ZAP report unavailable</title>\n' > "$results_dir/E012-zap-baseline.html"

printf '{"tool": "OWASP ZAP baseline", "target": "%s", "scan_mode": "passive baseline only", "exit_code": %s}\n' \
  "$target_url" "$zap_status" > "$results_dir/E013-zap-baseline-exit-code.json"

cp "$results_dir"/* "$evidence_dir"/

# Evidence collection baseline: alert review and policy gates come later.
exit 0
