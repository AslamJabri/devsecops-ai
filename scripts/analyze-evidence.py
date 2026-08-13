#!/usr/bin/env python3
"""
Project 25 deterministic evidence analysis.

Purpose:
- Read scanner-generated evidence.
- Normalize counts and severity context.
- Produce a trusted local summary (E014).
- Produce a human-reviewable MITRE/D3FEND worksheet (E015).

Important:
This script is deterministic and does not use AI.
AI analysis happens only after E014 is generated.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def load_json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return fallback


def normalize_severity(value: Any) -> str:
    severity = str(value or "UNKNOWN").strip().upper()

    if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return severity

    return "UNKNOWN"


def count_trivy_vulnerabilities(report: dict[str, Any]) -> int:
    return sum(
        len(result.get("Vulnerabilities") or [])
        for result in report.get("Results") or []
    )


def trivy_severity_counts(report: dict[str, Any]) -> Counter:
    counts: Counter = Counter()

    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            counts[normalize_severity(vuln.get("Severity"))] += 1

    return counts


def bandit_severity_counts(report: dict[str, Any]) -> Counter:
    counts: Counter = Counter()

    for finding in report.get("results") or []:
        counts[
            normalize_severity(
                finding.get("issue_severity")
            )
        ] += 1

    return counts


def pip_audit_vulnerability_count(dependencies: list[dict[str, Any]]) -> int:
    return sum(
        len(item.get("vulns") or [])
        for item in dependencies
    )


def severity_weight(severity: str) -> int:
    return {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 1,
        "UNKNOWN": 0,
    }.get(severity, 0)


def deterministic_risk_score(
    gitleaks_count: int,
    bandit_counts: Counter,
    dependency_count: int,
    trivy_counts: Counter,
) -> dict[str, Any]:
    """
    Simple Project 25 baseline scoring model.

    This is intentionally transparent and deterministic.
    It is not a replacement for CVSS or organizational risk methodology.

    Maximum score: 100.
    """

    score = 0

    # Secret exposure is treated as significant in a CI/CD context.
    if gitleaks_count > 0:
        score += min(20, gitleaks_count * 10)

    # Static-analysis findings.
    for severity, count in bandit_counts.items():
        score += count * severity_weight(severity)

    # Dependency vulnerabilities.
    score += min(25, dependency_count * 4)

    # Container vulnerabilities.
    for severity, count in trivy_counts.items():
        score += count * severity_weight(severity)

    score = min(score, 100)

    if score >= 80:
        rating = "critical"
    elif score >= 60:
        rating = "high"
    elif score >= 30:
        rating = "medium"
    elif score > 0:
        rating = "low"
    else:
        rating = "informational"

    return {
        "score": score,
        "rating": rating,
        "method": "project25-deterministic-baseline-v1",
        "notes": [
            "This score is a local lab prioritization aid.",
            "It is not a replacement for CVSS or organizational risk acceptance.",
            "AI is not permitted to modify this score.",
        ],
    }


def copy_reports_to_evidence(
    output_dir: Path,
    evidence_dir: Path,
) -> None:
    for report in output_dir.iterdir():
        if report.is_file():
            (evidence_dir / report.name).write_bytes(
                report.read_bytes()
            )


def main() -> None:
    scan_dir = Path(
        sys.argv[1] if len(sys.argv) > 1 else "scan-results"
    )
    container_dir = Path(
        sys.argv[2] if len(sys.argv) > 2 else "container-results"
    )
    output_dir = Path(
        sys.argv[3] if len(sys.argv) > 3 else "analysis-results"
    )
    evidence_dir = Path(
        sys.argv[4]
        if len(sys.argv) > 4
        else "/opt/project25/evidence/generated"
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------
    # Load evidence
    # ---------------------------------------------------------

    gitleaks = load_json(
        scan_dir / "E004-gitleaks.json",
        [],
    )

    bandit = load_json(
        scan_dir / "E005-bandit.json",
        {"results": []},
    )

    pip_audit = load_json(
        scan_dir / "E006-pip-audit.json",
        [],
    )

    if isinstance(pip_audit, dict):
        pip_audit = pip_audit.get("dependencies", [])

    if not isinstance(pip_audit, list):
        pip_audit = []

    scan_exit_codes = load_json(
        scan_dir / "E007-scan-exit-codes.json",
        {},
    )

    trivy = load_json(
        container_dir / "E009-trivy-image.json",
        {"Results": []},
    )

    container_exit_codes = load_json(
        container_dir / "E010-container-scan-exit-codes.json",
        {},
    )

    # ---------------------------------------------------------
    # Calculate deterministic counts
    # ---------------------------------------------------------

    gitleaks_count = (
        len(gitleaks)
        if isinstance(gitleaks, list)
        else 0
    )

    bandit_findings = bandit.get("results") or []
    bandit_count = len(bandit_findings)
    bandit_counts = bandit_severity_counts(bandit)

    dependency_count = pip_audit_vulnerability_count(
        pip_audit
    )

    trivy_count = count_trivy_vulnerabilities(trivy)
    trivy_counts = trivy_severity_counts(trivy)

    critical_count = (
        bandit_counts["CRITICAL"]
        + trivy_counts["CRITICAL"]
    )

    high_count = (
        bandit_counts["HIGH"]
        + trivy_counts["HIGH"]
    )

    medium_count = (
        bandit_counts["MEDIUM"]
        + trivy_counts["MEDIUM"]
    )

    low_count = (
        bandit_counts["LOW"]
        + trivy_counts["LOW"]
    )

    risk_score = deterministic_risk_score(
        gitleaks_count=gitleaks_count,
        bandit_counts=bandit_counts,
        dependency_count=dependency_count,
        trivy_counts=trivy_counts,
    )

    # ---------------------------------------------------------
    # E014 — trusted local summary
    # ---------------------------------------------------------

    summary = {
        "evidence_packet": "E014",
        "schema_version": "1.0",
        "scope": (
            "Project 25 local pre-deployment "
            "DevSecOps assessment only"
        ),
        "assessment_phase": "baseline",
        "disposition": (
            "Human review required. Scanner observations "
            "are not automatic risk conclusions, proof of "
            "adversary behavior, or final ATT&CK mappings."
        ),
        "source_evidence": [
            "E004",
            "E005",
            "E006",
            "E007",
            "E009",
            "E010",
        ],
        "observations": [
            {
                "evidence_id": "E004",
                "tool": "Gitleaks",
                "category": "secret_scanning",
                "observation_count": gitleaks_count,
                "summary": (
                    "Potential secret matches identified by "
                    "repository secret scanning."
                ),
                "trust_level": "scanner-generated",
                "requires_human_validation": True,
            },
            {
                "evidence_id": "E005",
                "tool": "Bandit",
                "category": "sast",
                "observation_count": bandit_count,
                "severity_counts": dict(bandit_counts),
                "summary": (
                    "Python static-analysis observations."
                ),
                "trust_level": "scanner-generated",
                "requires_human_validation": True,
            },
            {
                "evidence_id": "E006",
                "tool": "pip-audit",
                "category": "dependency_security",
                "observation_count": dependency_count,
                "summary": (
                    "Known dependency vulnerability "
                    "observations."
                ),
                "trust_level": "scanner-generated",
                "requires_human_validation": True,
            },
            {
                "evidence_id": "E009",
                "tool": "Trivy",
                "category": "container_security",
                "observation_count": trivy_count,
                "severity_counts": dict(trivy_counts),
                "summary": (
                    "Known vulnerabilities observed in the "
                    "built local container image."
                ),
                "trust_level": "scanner-generated",
                "requires_human_validation": True,
            },
        ],
        "scanner_exit_codes": {
            "E007": scan_exit_codes,
            "E010": container_exit_codes,
        },
        "risk_context": {
            "secret_scan_observations": gitleaks_count,
            "sast_observations": bandit_count,
            "dependency_vulnerabilities": dependency_count,
            "container_vulnerabilities": trivy_count,
            "critical_findings": critical_count,
            "high_findings": high_count,
            "medium_findings": medium_count,
            "low_findings": low_count,
            "baseline_enforcement_enabled": False,
            "assessment_environment": "local-lab",
        },
        "risk_score": risk_score,
        "ai_policy": {
            "authority": "advisory-only",
            "may_modify_risk_score": False,
            "may_approve_deployment": False,
            "may_modify_pipeline": False,
            "may_create_final_mitre_mapping": False,
            "human_verification_required": True,
        },
        "recommended_human_actions": [
            (
                "Validate each observation against source, "
                "dependency, and image context."
            ),
            (
                "Prioritize confirmed high-impact findings "
                "for mitigation."
            ),
            (
                "Do not map scanner observations to ATT&CK "
                "unless adversary behavior was safely "
                "demonstrated or independently supported "
                "by evidence."
            ),
            (
                "Verify applicable D3FEND techniques against "
                "the current D3FEND knowledge base."
            ),
            (
                "After mitigation, rerun the identical "
                "pipeline and compare before/after evidence."
            ),
        ],
    }

    # ---------------------------------------------------------
    # E015 — human MITRE / D3FEND worksheet
    # ---------------------------------------------------------

    worksheet = {
        "evidence_packet": "E015",
        "schema_version": "1.0",
        "status": (
            "Candidate mapping worksheet — "
            "human verification required"
        ),
        "rules": [
            (
                "A vulnerability or static finding alone is "
                "not proof that an ATT&CK technique occurred."
            ),
            (
                "Record ATT&CK only for behavior safely "
                "demonstrated in scope or independently "
                "supported by evidence."
            ),
            (
                "Record D3FEND controls as proposed or "
                "implemented mitigations and link validation "
                "evidence."
            ),
            (
                "AI recommendations are advisory and cannot "
                "be accepted without human verification."
            ),
        ],
        "review_rows": [
            {
                "evidence_ids": ["E004"],
                "observation": "Secret scanning result",
                "ATT&CK_status": (
                    "Do not map unless credential access, "
                    "exposure, or use is demonstrated with "
                    "supporting evidence."
                ),
                "D3FEND_control_to_review": (
                    "Credential management and secret scanning"
                ),
                "reviewer_decision": "pending",
            },
            {
                "evidence_ids": ["E005"],
                "observation": "Static-analysis result",
                "ATT&CK_status": (
                    "No ATT&CK technique inferred from a "
                    "code-quality or static-analysis finding "
                    "alone."
                ),
                "D3FEND_control_to_review": (
                    "Static code analysis"
                ),
                "reviewer_decision": "pending",
            },
            {
                "evidence_ids": ["E006", "E009"],
                "observation": (
                    "Dependency or container-image "
                    "vulnerability result"
                ),
                "ATT&CK_status": (
                    "No ATT&CK technique inferred solely "
                    "from vulnerability presence."
                ),
                "D3FEND_control_to_review": (
                    "Software composition analysis and "
                    "container image scanning"
                ),
                "reviewer_decision": "pending",
            },
        ],
    }

    # ---------------------------------------------------------
    # Write artifacts
    # ---------------------------------------------------------

    e014_path = (
        output_dir
        / "E014-local-analysis-summary.json"
    )

    e015_path = (
        output_dir
        / "E015-mitre-d3fend-review-worksheet.json"
    )

    e014_path.write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )

    e015_path.write_text(
        json.dumps(worksheet, indent=2) + "\n",
        encoding="utf-8",
    )

    copy_reports_to_evidence(
        output_dir=output_dir,
        evidence_dir=evidence_dir,
    )

    print(
        f"[Project25] Generated {e014_path}"
    )
    print(
        f"[Project25] Generated {e015_path}"
    )
    print(
        "[Project25] Deterministic risk score: "
        f"{risk_score['score']}/100 "
        f"({risk_score['rating']})"
    )


if __name__ == "__main__":
    main()