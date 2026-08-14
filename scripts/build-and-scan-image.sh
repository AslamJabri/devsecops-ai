#!/usr/bin/env bash

set -u

TARGET_DIR="${1:-target}"
OUTPUT_DIR="${2:-container-results}"
EVIDENCE_DIR="${3:-/opt/devshield/evidence/generated}"

IMAGE_NAME="${DEVSHIELD_IMAGE_NAME:-devshield-demo-app:baseline}"

mkdir -p "$OUTPUT_DIR"
mkdir -p "$EVIDENCE_DIR"

echo "[DevShield] Container assessment"
echo "[DevShield] Target: $TARGET_DIR"
echo "[DevShield] Image: $IMAGE_NAME"

BUILD_EXIT=0
TRIVY_EXIT=0


# --------------------------------------------------
# Find Dockerfile
# --------------------------------------------------

DOCKERFILE=""

if [ -f "$TARGET_DIR/Dockerfile" ]; then
  DOCKERFILE="$TARGET_DIR/Dockerfile"
else
  DOCKERFILE="$(
    find "$TARGET_DIR" \
      -maxdepth 3 \
      -type f \
      -iname 'Dockerfile*' \
      | head -n 1
  )"
fi


# --------------------------------------------------
# Build
# --------------------------------------------------

if [ -n "$DOCKERFILE" ]; then
  BUILD_CONTEXT="$(dirname "$DOCKERFILE")"

  echo "[DevShield] Dockerfile: $DOCKERFILE"
  echo "[DevShield] Build context: $BUILD_CONTEXT"

  docker build \
    -t "$IMAGE_NAME" \
    -f "$DOCKERFILE" \
    "$BUILD_CONTEXT"

  BUILD_EXIT=$?
else
  echo "[DevShield] No Dockerfile found."

  BUILD_EXIT=2
fi


# --------------------------------------------------
# Trivy
# --------------------------------------------------

if [ "$BUILD_EXIT" -eq 0 ]; then
  echo "[DevShield] Running Trivy..."

  trivy image \
    --format json \
    --output "$OUTPUT_DIR/E009-trivy-image.json" \
    "$IMAGE_NAME"

  TRIVY_EXIT=$?
else
  echo "[DevShield] Image build failed/skipped; Trivy image scan skipped."

  cat > "$OUTPUT_DIR/E009-trivy-image.json" <<'EOF'
{
  "Results": [],
  "devshield_status": "skipped",
  "reason": "Container image was not successfully built"
}
EOF

  TRIVY_EXIT=2
fi


# --------------------------------------------------
# E010
# --------------------------------------------------

python3 - \
  "$OUTPUT_DIR/E010-container-scan-exit-codes.json" \
  "$BUILD_EXIT" \
  "$TRIVY_EXIT" <<'PY'
import json
import sys

output = sys.argv[1]

data = {
    "docker_build": int(sys.argv[2]),
    "trivy": int(sys.argv[3]),
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
  "$OUTPUT_DIR/E009-trivy-image.json" \
  "$OUTPUT_DIR/E010-container-scan-exit-codes.json"
do
  if [ -f "$report" ]; then
    cp "$report" "$EVIDENCE_DIR/"
  fi
done


echo "[DevShield] Container assessment complete."
echo "[DevShield] Baseline mode: build/scan findings do not fail the pipeline."

exit 0
