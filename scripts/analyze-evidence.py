#!/usr/bin/env python3
"""Create a local, human-reviewable analysis packet from Project 25 evidence."""

import json
import sys
from pathlib import Path


def load_json(path, fallback):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return fallback


def count_trivy_vulnerabilities(report):
    return sum(
        len(result.get("Vulnerabilities") or [])
        for result in report.get("Results") or []
    )


def main():
    scan_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "scan-results")
    container_dir = Path(sys.argv[2] if len(sys.argv) > 2 else "container-results")
    output_dir = Path(sys.argv[3] if len(sys.argv) > 3 else "analysis-results")
    evidence_dir = Path(
        sys.argv[4] if len(sys.argv) > 4 else "/opt/project25/evidence/generated"
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    gitleaks = load_json(scan_dir / "E004-gitleaks.json", [])
    bandit = load_json(scan_dir / "E005-bandit.json", {"results": []})
    pip_audit = load_json(scan_dir / "E006-pip-audit.json", [])
    if isinstance(pip_audit, dict):
        pip_audit = pip_audit.get("dependencies", [])
    if not isinstance(pip_audit, list):
        pip_audit = []

    scan_exit_codes = load_json(scan_dir / "E007-scan-exit-codes.json", {})
    trivy = load_json(container_dir / "E009-trivy-image.json", {"Results": []})
    container_exit_codes = load_json(
        container_dir / "E010-container-scan-exit-codes.json", {}
    )

    summary = {
        "evidence_packet": "E014",
        "scope": "Project 25 local pre-deployment assessment only",
        "disposition": (
            "Human review required; observations are not automatic risk "
            "conclusions or ATT&CK claims."
        ),
        "source_evidence": ["E004", "E005", "E006", "E007", "E009", "E010"],
        "observations": [
            {
                "evidence_id": "E004",
                "tool": "Gitleaks",
                "observation_count": len(gitleaks),
                "summary": "Potential secret matches are redacted by the scanner.",
            },
            {
                "evidence_id": "E005",
                "tool": "Bandit",
                "observation_count": len(bandit.get("results") or []),
                "summary": "Python static-analysis observations.",
            },
            {
                "evidence_id": "E006",
                "tool": "pip-audit",
                "observation_count": sum(
                    len(item.get("vulns") or []) for item in pip_audit
                ),
                "summary": "Known dependency vulnerability observations.",
            },
            {
                "evidence_id": "E009",
                "tool": "Trivy",
                "observation_count": count_trivy_vulnerabilities(trivy),
                "summary": (
                    "Known vulnerabilities observed in the built local "
                    "container image."
                ),
            },
        ],
        "scanner_exit_codes": {
            "E007": scan_exit_codes,
            "E010": container_exit_codes,
        },
        "recommended_human_actions": [
            "Validate each observation against source, dependency, and image context.",
            "Prioritize a dependency update or compensating control for confirmed vulnerabilities.",
            "Do not map a scanner observation to ATT&CK unless adversary behavior was demonstrated.",
            "After mitigation, rerun this identical pipeline and compare evidence.",
        ],
    }

    worksheet = {
        "evidence_packet": "E015",
        "status": "Candidate mapping worksheet — human verification required",
        "rules": [
            "A vulnerability or static finding alone is not proof that an ATT&CK technique occurred.",
            "Record ATT&CK only for behavior demonstrated safely in scope or supported by evidence.",
            "Record D3FEND controls as proposed or implemented mitigations and link validation evidence.",
        ],
        "review_rows": [
            {
                "evidence_ids": ["E004"],
                "observation": "Secret scanning result",
                "ATT&CK_status": "Do not map unless credential access or use is demonstrated",
                "D3FEND_control_to_review": "Credential management and secret scanning",
                "reviewer_decision": "pending",
            },
            {
                "evidence_ids": ["E005"],
                "observation": "Static-analysis result",
                "ATT&CK_status": "No technique inferred from code finding alone",
                "D3FEND_control_to_review": "Static code analysis",
                "reviewer_decision": "pending",
            },
            {
                "evidence_ids": ["E006", "E009"],
                "observation": "Dependency or image vulnerability result",
                "ATT&CK_status": "No technique inferred from vulnerability presence alone",
                "D3FEND_control_to_review": (
                    "Software composition analysis; container image scanning"
                ),
                "reviewer_decision": "pending",
            },
        ],
    }

    (output_dir / "E014-local-analysis-summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    (output_dir / "E015-mitre-d3fend-review-worksheet.json").write_text(
        json.dumps(worksheet, indent=2) + "\n", encoding="utf-8"
    )

    for report in output_dir.iterdir():
        (evidence_dir / report.name).write_bytes(report.read_bytes())


if __name__ == "__main__":
    main()