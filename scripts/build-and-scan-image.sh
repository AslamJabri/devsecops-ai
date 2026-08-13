#!/bin/sh
# Project 25: build and scan only the local demo image. No registry push occurs.
set +e

results_dir="${1:-container-results}"
evidence_dir="${2:-/opt/project25/evidence/generated}"
image_name="project25-demo-app:${BUILD_NUMBER:-local}"

mkdir -p "$results_dir" "$evidence_dir"

docker build --tag "$image_name" demo-app
build_status=$?

if [ "$build_status" -eq 0 ]; then
  docker image inspect "$image_name" > "$results_dir/E008-container-image-metadata.json"
  inspect_status=$?
  trivy image --scanners vuln --format json --output "$results_dir/E009-trivy-image.json" "$image_name"
  trivy_status=$?
else
  printf '{"status": "image build failed; image inspection and Trivy scan were not run"}\n' \
    > "$results_dir/E008-container-image-metadata.json"
  printf '{"Results": []}\n' > "$results_dir/E009-trivy-image.json"
  inspect_status=1
  trivy_status=1
fi

printf '{"image": "%s", "docker_build_exit_code": %s, "image_inspect_exit_code": %s, "trivy_exit_code": %s}\n' \
  "$image_name" "$build_status" "$inspect_status" "$trivy_status" \
  > "$results_dir/E010-container-scan-exit-codes.json"

cp "$results_dir"/* "$evidence_dir"/

# Evidence collection baseline: later validation introduces a blocking policy.
exit 0
