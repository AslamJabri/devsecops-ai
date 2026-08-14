#!/usr/bin/env bash

set -u

TARGET_DIR="${1:-target}"
OUTPUT_DIR="${2:-scan-results}"
EVIDENCE_DIR="${3:-/opt/sentinelforge/evidence/generated}"

mkdir -p "$OUTPUT_DIR"
mkdir -p "$EVIDENCE_DIR"

echo "[SentinelForge] Target directory: $TARGET_DIR"
echo "[SentinelForge] Output directory: $OUTPUT_DIR"

# --------------------------------------------------
# E004 - Gitleaks
# --------------------------------------------------

echo "[SentinelForge] Running Gitleaks..."

gitleaks detect \
  --source "$TARGET_DIR" \
  --no-git \
  --report-format json \
  --report-path "$OUTPUT_DIR/E004-gitleaks.json"

GITLEAKS_EXIT=$?

# Gitleaks may not create a report when nothing is found.
if [ ! -f "$OUTPUT_DIR/E004-gitleaks.json" ]; then
  echo "[]" > "$OUTPUT_DIR/E004-gitleaks.json"
fi


# --------------------------------------------------
# E005 - Bandit
# --------------------------------------------------

echo "[SentinelForge] Running Bandit..."

bandit \
  -r "$TARGET_DIR" \
  -f json \
  -o "$OUTPUT_DIR/E005-bandit.json"

BANDIT_EXIT=$?

if [ ! -f "$OUTPUT_DIR/E005-bandit.json" ]; then
  echo '{"results":[]}' > "$OUTPUT_DIR/E005-bandit.json"
fi


# --------------------------------------------------
# E006 - pip-audit
# --------------------------------------------------

echo "[SentinelForge] Running pip-audit..."

PIP_AUDIT_EXIT=0

REQUIREMENTS_FILE=""

if [ -f "$TARGET_DIR/requirements.txt" ]; then
  REQUIREMENTS_FILE="$TARGET_DIR/requirements.txt"
else
  REQUIREMENTS_FILE="$(
    find "$TARGET_DIR" \
      -maxdepth 3 \
      -type f \
      -name 'requirements*.txt' \
      | head -n 1
  )"
fi

if [ -n "$REQUIREMENTS_FILE" ]; then
  echo "[SentinelForge] Requirements file: $REQUIREMENTS_FILE"

  pip-audit \
    -r "$REQUIREMENTS_FILE" \
    -f json \
    -o "$OUTPUT_DIR/E006-pip-audit.json"

  PIP_AUDIT_EXIT=$?
else
  echo "[SentinelForge] No requirements file found."

  cat > "$OUTPUT_DIR/E006-pip-audit.json" <<'EOF'
{
  "dependencies": [],
  "sentinelforge_status": "skipped",
  "reason": "No requirements file found"
}
EOF

  PIP_AUDIT_EXIT=0
fi


# --------------------------------------------------
# E007 - scanner exit codes
# --------------------------------------------------

python3 - \
  "$OUTPUT_DIR/E007-scan-exit-codes.json" \
  "$GITLEAKS_EXIT" \
  "$BANDIT_EXIT" \
  "$PIP_AUDIT_EXIT" <<'PY'
import json
import sys

output = sys.argv[1]

data = {
    "gitleaks": int(sys.argv[2]),
    "bandit": int(sys.argv[3]),
    "pip_audit": int(sys.argv[4]),
    "baseline_enforcement": False,
}

with open(output, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2)
    handle.write("\n")
PY


# --------------------------------------------------
# Copy evidence
# --------------------------------------------------

for report in \
  "$OUTPUT_DIR/E004-gitleaks.json" \
  "$OUTPUT_DIR/E005-bandit.json" \
  "$OUTPUT_DIR/E006-pip-audit.json" \
  "$OUTPUT_DIR/E007-scan-exit-codes.json"
do
  if [ -f "$report" ]; then
    cp "$report" "$EVIDENCE_DIR/"
  fi
done


# --------------------------------------------------
# Baseline behavior
# --------------------------------------------------

echo "[SentinelForge] Repository assessment complete."
echo "[SentinelForge] Baseline mode: scanner findings do not fail the pipeline."

exit 0
