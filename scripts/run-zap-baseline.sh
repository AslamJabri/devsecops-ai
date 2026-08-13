#!/bin/sh
# Project 25: passive, local-only DAST baseline. No active attack scan is run.
set +e

results_dir="${1:-dast-results}"
evidence_dir="${2:-/opt/project25/evidence/generated}"
workspace="${3:?Jenkins workspace path is required}"
target_url="${PROJECT25_DAST_TARGET:-http://host.docker.internal:5001}"
docker_network="${PROJECT25_DOCKER_NETWORK:-project25-devsecops-lab_default}"
jenkins_container="$(hostname)"
jenkins_home_volume="$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/jenkins_home"}}{{.Name}}{{end}}{{end}}' "$jenkins_container")"

mkdir -p "$results_dir" "$evidence_dir"

if [ -z "$jenkins_home_volume" ]; then
  printf '{"site": [], "alerts": [], "error": "Jenkins home volume was not found"}\n' > "$results_dir/E011-zap-baseline.json"
  printf '<!doctype html><title>ZAP report unavailable</title>\n' > "$results_dir/E012-zap-baseline.html"
  printf '{"tool": "OWASP ZAP baseline", "target": "%s", "scan_mode": "passive baseline only", "exit_code": 1}\n' \
    "$target_url" > "$results_dir/E013-zap-baseline-exit-code.json"
  cp "$results_dir"/* "$evidence_dir"/
  exit 0
fi

# ZAP requires file reports beneath its /zap/wrk mount. The named Jenkins-home
# volume contains this job's workspace and is mounted there temporarily.
zap_report_dir="/zap/wrk/workspace/$(basename "$workspace")/$results_dir"
docker run --rm \
  --volume "$jenkins_home_volume:/zap/wrk" \
  --user root \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t "$target_url" -m 1 -I \
  -J "$zap_report_dir/E011-zap-baseline.json" \
  -r "$zap_report_dir/E012-zap-baseline.html"
zap_status=$?

test -f "$results_dir/E011-zap-baseline.json" || printf '{"site": [], "alerts": []}\n' > "$results_dir/E011-zap-baseline.json"
test -f "$results_dir/E012-zap-baseline.html" || printf '<!doctype html><title>ZAP report unavailable</title>\n' > "$results_dir/E012-zap-baseline.html"

printf '{"tool": "OWASP ZAP baseline", "target": "%s", "scan_mode": "passive baseline only", "exit_code": %s}\n' \
  "$target_url" "$zap_status" > "$results_dir/E013-zap-baseline-exit-code.json"

cp "$results_dir"/* "$evidence_dir"/

# Evidence collection baseline: alert review and policy gates come later.
exit 0
