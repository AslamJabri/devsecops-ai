#!/usr/bin/env python3
"""
Project 25 evidence-grounded Gemini security analysis.

Security design:
- Sends E014 only.
- Never sends raw scanner reports.
- Never sends source code.
- Never sends credentials.
- AI is advisory only.
- Gemini response must conform to structured JSON.
- Referenced evidence IDs are validated locally.
- Deterministic risk score cannot be modified by AI.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def canonical_json(data: Any) -> str:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def write_json(
    path: Path,
    data: Any,
) -> None:
    path.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


def copy_to_evidence(
    paths: list[Path],
    evidence_dir: Path,
) -> None:
    for path in paths:
        if path.exists():
            (
                evidence_dir / path.name
            ).write_bytes(
                path.read_bytes()
            )


def write_artifacts(
    report_path: Path,
    metadata_path: Path,
    structured_path: Path,
    evidence_dir: Path,
    report_text: str,
    metadata: dict[str, Any],
    structured_output: dict[str, Any],
) -> None:
    report_path.write_text(
        report_text,
        encoding="utf-8",
    )

    write_json(
        metadata_path,
        metadata,
    )

    write_json(
        structured_path,
        structured_output,
    )

    copy_to_evidence(
        [
            report_path,
            metadata_path,
            structured_path,
        ],
        evidence_dir,
    )


def extract_candidate_text(
    result: dict[str, Any],
) -> str:
    candidates = result.get("candidates") or []

    if not candidates:
        return ""

    content = (
        candidates[0].get("content")
        or {}
    )

    parts = content.get("parts") or []

    return "".join(
        part.get("text", "")
        for part in parts
        if isinstance(part, dict)
    ).strip()


# ---------------------------------------------------------
# Structured-output schema
# ---------------------------------------------------------


AI_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": {
            "type": "string",
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                    },
                    "title": {
                        "type": "string",
                    },
                    "evidence_ids": {
                        "type": "array",
                        "items": {
                            "type": "string",
                        },
                    },
                    "priority": {
                        "type": "string",
                        "enum": [
                            "critical",
                            "high",
                            "medium",
                            "low",
                            "informational",
                        ],
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                    "analysis": {
                        "type": "string",
                    },
                    "root_cause_candidate": {
                        "type": "string",
                    },
                    "remediation": {
                        "type": "array",
                        "items": {
                            "type": "string",
                        },
                    },
                },
                "required": [
                    "finding_id",
                    "title",
                    "evidence_ids",
                    "priority",
                    "confidence",
                    "analysis",
                    "root_cause_candidate",
                    "remediation",
                ],
            },
        },
        "correlations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "evidence_ids": {
                        "type": "array",
                        "items": {
                            "type": "string",
                        },
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                    "analysis": {
                        "type": "string",
                    },
                },
                "required": [
                    "evidence_ids",
                    "confidence",
                    "analysis",
                ],
            },
        },
        "mitre_candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "evidence_ids": {
                        "type": "array",
                        "items": {
                            "type": "string",
                        },
                    },
                    "technique_id": {
                        "type": [
                            "string",
                            "null",
                        ],
                    },
                    "technique_name": {
                        "type": [
                            "string",
                            "null",
                        ],
                    },
                    "status": {
                        "type": "string",
                        "enum": [
                            "candidate",
                            "insufficient_evidence",
                        ],
                    },
                    "reason": {
                        "type": "string",
                    },
                    "human_verification_required": {
                        "type": "boolean",
                    },
                },
                "required": [
                    "evidence_ids",
                    "technique_id",
                    "technique_name",
                    "status",
                    "reason",
                    "human_verification_required",
                ],
            },
        },
        "d3fend_candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "evidence_ids": {
                        "type": "array",
                        "items": {
                            "type": "string",
                        },
                    },
                    "control": {
                        "type": "string",
                    },
                    "status": {
                        "type": "string",
                    },
                    "reason": {
                        "type": "string",
                    },
                    "human_verification_required": {
                        "type": "boolean",
                    },
                },
                "required": [
                    "evidence_ids",
                    "control",
                    "status",
                    "reason",
                    "human_verification_required",
                ],
            },
        },
        "recommended_actions": {
            "type": "array",
            "items": {
                "type": "string",
            },
        },
        "limitations": {
            "type": "array",
            "items": {
                "type": "string",
            },
        },
    },
    "required": [
        "executive_summary",
        "findings",
        "correlations",
        "mitre_candidates",
        "d3fend_candidates",
        "recommended_actions",
        "limitations",
    ],
}


# ---------------------------------------------------------
# Validation
# ---------------------------------------------------------


def validate_evidence_references(
    ai_output: dict[str, Any],
    allowed_evidence_ids: set[str],
) -> list[str]:
    errors: list[str] = []

    sections = [
        "findings",
        "correlations",
        "mitre_candidates",
        "d3fend_candidates",
    ]

    for section in sections:
        rows = ai_output.get(section, [])

        if not isinstance(rows, list):
            errors.append(
                f"{section} must be a list"
            )
            continue

        for index, row in enumerate(rows):
            evidence_ids = (
                row.get("evidence_ids", [])
                if isinstance(row, dict)
                else []
            )

            if not evidence_ids:
                errors.append(
                    f"{section}[{index}] "
                    "contains no evidence IDs"
                )
                continue

            for evidence_id in evidence_ids:
                if (
                    evidence_id
                    not in allowed_evidence_ids
                ):
                    errors.append(
                        f"{section}[{index}] "
                        "references unknown evidence ID "
                        f"{evidence_id}"
                    )

    return errors


def validate_ai_authority(
    ai_output: dict[str, Any],
) -> list[str]:
    errors: list[str] = []

    for row in ai_output.get(
        "mitre_candidates",
        [],
    ):
        if not row.get(
            "human_verification_required",
            False,
        ):
            errors.append(
                "MITRE candidate omitted required "
                "human verification flag"
            )

    for row in ai_output.get(
        "d3fend_candidates",
        [],
    ):
        if not row.get(
            "human_verification_required",
            False,
        ):
            errors.append(
                "D3FEND candidate omitted required "
                "human verification flag"
            )

    return errors


# ---------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------


def render_markdown(
    ai_output: dict[str, Any],
    deterministic_risk_score: dict[str, Any],
) -> str:
    lines: list[str] = []

    lines.append(
        "# AI Security Analysis — Human Review Required"
    )
    lines.append("")

    lines.append(
        "## Deterministic Risk Context"
    )
    lines.append("")

    lines.append(
        f"- Score: "
        f"{deterministic_risk_score.get('score', 'unknown')}/100"
    )

    lines.append(
        f"- Rating: "
        f"{deterministic_risk_score.get('rating', 'unknown')}"
    )

    lines.append(
        "- Authority: deterministic local analysis; "
        "AI cannot modify this score."
    )
    lines.append("")

    lines.append(
        "## Executive Summary"
    )
    lines.append("")

    lines.append(
        ai_output.get(
            "executive_summary",
            "No executive summary returned.",
        )
    )
    lines.append("")

    lines.append(
        "## Evidence-Based Findings"
    )
    lines.append("")

    findings = ai_output.get(
        "findings",
        [],
    )

    if not findings:
        lines.append(
            "No AI findings were generated."
        )
        lines.append("")

    for finding in findings:
        lines.append(
            f"### {finding.get('finding_id')} — "
            f"{finding.get('title')}"
        )
        lines.append("")

        lines.append(
            f"- Priority: {finding.get('priority')}"
        )
        lines.append(
            f"- Confidence: {finding.get('confidence')}"
        )
        lines.append(
            "- Evidence: "
            + ", ".join(
                finding.get(
                    "evidence_ids",
                    [],
                )
            )
        )
        lines.append("")

        lines.append(
            finding.get(
                "analysis",
                "",
            )
        )
        lines.append("")

        lines.append(
            "**Root-cause candidate:** "
            + finding.get(
                "root_cause_candidate",
                "",
            )
        )
        lines.append("")

        remediation = finding.get(
            "remediation",
            [],
        )

        if remediation:
            lines.append(
                "**Recommended remediation:**"
            )

            for item in remediation:
                lines.append(
                    f"- {item}"
                )

            lines.append("")

    lines.append(
        "## Correlations"
    )
    lines.append("")

    correlations = ai_output.get(
        "correlations",
        [],
    )

    if not correlations:
        lines.append(
            "No evidence correlations were proposed."
        )
        lines.append("")

    for correlation in correlations:
        lines.append(
            "- Evidence "
            + ", ".join(
                correlation.get(
                    "evidence_ids",
                    [],
                )
            )
            + f" — confidence "
            + str(
                correlation.get(
                    "confidence"
                )
            )
        )

        lines.append(
            f"  {correlation.get('analysis', '')}"
        )

    lines.append("")

    lines.append(
        "## MITRE ATT&CK Candidates"
    )
    lines.append("")

    mitre = ai_output.get(
        "mitre_candidates",
        [],
    )

    if not mitre:
        lines.append(
            "No ATT&CK candidates proposed."
        )

    for candidate in mitre:
        technique = (
            candidate.get("technique_id")
            or "No technique assigned"
        )

        technique_name = (
            candidate.get("technique_name")
            or ""
        )

        lines.append(
            f"- {technique} {technique_name}".rstrip()
        )
        lines.append(
            "  - Evidence: "
            + ", ".join(
                candidate.get(
                    "evidence_ids",
                    [],
                )
            )
        )
        lines.append(
            f"  - Status: "
            f"{candidate.get('status')}"
        )
        lines.append(
            f"  - Reason: "
            f"{candidate.get('reason')}"
        )
        lines.append(
            "  - Human verification required: yes"
        )

    lines.append("")

    lines.append(
        "## D3FEND Candidates"
    )
    lines.append("")

    d3fend = ai_output.get(
        "d3fend_candidates",
        [],
    )

    if not d3fend:
        lines.append(
            "No D3FEND candidates proposed."
        )

    for candidate in d3fend:
        lines.append(
            f"- {candidate.get('control')}"
        )
        lines.append(
            "  - Evidence: "
            + ", ".join(
                candidate.get(
                    "evidence_ids",
                    [],
                )
            )
        )
        lines.append(
            f"  - Reason: "
            f"{candidate.get('reason')}"
        )
        lines.append(
            "  - Human verification required: yes"
        )

    lines.append("")

    lines.append(
        "## Recommended Actions"
    )
    lines.append("")

    for action in ai_output.get(
        "recommended_actions",
        [],
    ):
        lines.append(
            f"- {action}"
        )

    lines.append("")

    lines.append(
        "## Limitations"
    )
    lines.append("")

    for limitation in ai_output.get(
        "limitations",
        [],
    ):
        lines.append(
            f"- {limitation}"
        )

    lines.append("")
    lines.append(
        "DAST remains deferred to an explicitly "
        "authorized staging target."
    )
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------


def main() -> None:
    analysis_dir = Path(
        sys.argv[1]
        if len(sys.argv) > 1
        else "analysis-results"
    )

    evidence_dir = Path(
        sys.argv[2]
        if len(sys.argv) > 2
        else "/opt/project25/evidence/generated"
    )

    analysis_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    evidence_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    summary_path = (
        analysis_dir
        / "E014-local-analysis-summary.json"
    )

    report_path = (
        analysis_dir
        / "E016-ai-security-analysis.md"
    )

    metadata_path = (
        analysis_dir
        / "E017-ai-analysis-metadata.json"
    )

    structured_path = (
        analysis_dir
        / "E018-ai-security-analysis.json"
    )

    api_key = os.environ.get(
        "GEMINI_API_KEY",
        "",
    ).strip()

    model = os.environ.get(
        "GEMINI_MODEL",
        "gemini-3.6-flash",
    ).strip()

    # ---------------------------------------------------------
    # No API key
    # ---------------------------------------------------------

    if not api_key:
        metadata = {
            "evidence_id": "E017",
            "status": "skipped",
            "provider": "Gemini",
            "reason": (
                "GEMINI_API_KEY is not configured"
            ),
            "external_data_sent": False,
            "ai_authority": "advisory-only",
            "human_verification_required": True,
            "generated_at": utc_now(),
        }

        structured_output = {
            "status": "skipped",
            "reason": (
                "GEMINI_API_KEY is not configured"
            ),
        }

        write_artifacts(
            report_path,
            metadata_path,
            structured_path,
            evidence_dir,
            (
                "# AI Security Analysis\n\n"
                "Skipped: GEMINI_API_KEY "
                "is not configured.\n"
            ),
            metadata,
            structured_output,
        )

        print(
            "[Project25] AI analysis skipped: "
            "GEMINI_API_KEY not configured."
        )
        return

    # ---------------------------------------------------------
    # Read E014
    # ---------------------------------------------------------

    try:
        evidence = json.loads(
            summary_path.read_text(
                encoding="utf-8"
            )
        )

    except (
        FileNotFoundError,
        json.JSONDecodeError,
    ) as exc:
        metadata = {
            "evidence_id": "E017",
            "status": "error",
            "provider": "Gemini",
            "error_type": type(exc).__name__,
            "external_data_sent": False,
            "generated_at": utc_now(),
        }

        write_artifacts(
            report_path,
            metadata_path,
            structured_path,
            evidence_dir,
            (
                "# AI Security Analysis\n\n"
                "Skipped: E014 evidence summary "
                "is unavailable or invalid.\n"
            ),
            metadata,
            {
                "status": "error",
                "reason": (
                    "E014 evidence summary "
                    "unavailable or invalid"
                ),
            },
        )
        return

    # ---------------------------------------------------------
    # Integrity metadata
    # ---------------------------------------------------------

    evidence_json = canonical_json(
        evidence
    )

    input_sha256 = sha256_text(
        evidence_json
    )

    allowed_evidence_ids = set(
        evidence.get(
            "source_evidence",
            [],
        )
    )

    deterministic_score = evidence.get(
        "risk_score",
        {},
    )

    # ---------------------------------------------------------
    # System instruction
    # ---------------------------------------------------------

    instructions = """
You are the AI security-analysis layer for Project 25,
a controlled local DevSecOps security assessment.

You are advisory only.

STRICT RULES:

1. Use only facts present in the supplied E014 evidence packet.

2. Never invent:
   - evidence IDs
   - vulnerabilities
   - CVEs
   - scanner results
   - source-code facts
   - exploitability
   - credentials
   - attacker behavior
   - ATT&CK techniques
   - D3FEND techniques

3. A scanner observation is NOT proof of attacker activity.

4. ATT&CK mappings require actual observed or safely simulated
   adversary behavior. If the evidence is insufficient, return
   status "insufficient_evidence" with null technique fields.

5. Every finding, correlation, ATT&CK candidate and D3FEND
   candidate must reference evidence IDs supplied by E014.

6. Do not modify, reinterpret, replace or recalculate the
   deterministic risk score supplied by E014.

7. AI recommendations are advisory only.

8. Production approval, IAM changes, deployment, credential
   rotation and security-policy changes require human control.

9. MITRE ATT&CK and D3FEND mappings require human verification.

10. DAST remains deferred to an explicitly authorized staging
    environment.

Analyze the evidence conservatively.
"""

    user_prompt = (
        "Analyze the following Project 25 E014 "
        "evidence summary.\n\n"
        + json.dumps(
            evidence,
            indent=2,
            ensure_ascii=False,
        )
    )

    # ---------------------------------------------------------
    # Gemini payload
    # ---------------------------------------------------------

    payload = {
        "systemInstruction": {
            "parts": [
                {
                    "text": instructions,
                }
            ]
        },
        "contents": [
            {
                "role": "user",
                "parts": [
                    {
                        "text": user_prompt,
                    }
                ],
            }
        ],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 3000,
            "responseMimeType": "application/json",
            "responseJsonSchema": AI_RESPONSE_SCHEMA,
        },
    }

    endpoint = (
        "https://generativelanguage.googleapis.com/"
        "v1beta/models/"
        + urllib.parse.quote(
            model,
            safe="",
        )
        + ":generateContent"
    )

    request = urllib.request.Request(
        endpoint,
        data=json.dumps(
            payload
        ).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
        },
        method="POST",
    )

    # ---------------------------------------------------------
    # Request Gemini
    # ---------------------------------------------------------

    try:
        with urllib.request.urlopen(
            request,
            timeout=90,
        ) as response:
            result = json.loads(
                response.read().decode(
                    "utf-8"
                )
            )

        output_text = extract_candidate_text(
            result
        )

        if not output_text:
            raise ValueError(
                "Gemini returned no text output"
            )

        # -----------------------------------------------------
        # Parse structured output
        # -----------------------------------------------------

        try:
            ai_output = json.loads(
                output_text
            )

        except json.JSONDecodeError as exc:
            debug_path = analysis_dir / "E018-ai-invalid-response.txt"

            debug_path.write_text(
                output_text + "\n",
                encoding="utf-8",
            )

            (evidence_dir / debug_path.name).write_bytes(
                debug_path.read_bytes()
            )

            raise ValueError(
                "Gemini returned invalid JSON. "
                "Raw response saved to "
                "E018-ai-invalid-response.txt"
            ) from exc

        # -----------------------------------------------------
        # Local guardrail validation
        # -----------------------------------------------------

        validation_errors = []

        validation_errors.extend(
            validate_evidence_references(
                ai_output,
                allowed_evidence_ids,
            )
        )

        validation_errors.extend(
            validate_ai_authority(
                ai_output
            )
        )

        if validation_errors:
            metadata = {
                "evidence_id": "E017",
                "status": "rejected",
                "provider": "Gemini",
                "model": model,
                "input": (
                    "E014 local analysis summary only"
                ),
                "input_sha256": input_sha256,
                "external_data_sent": True,
                "raw_scanner_output_sent": False,
                "raw_source_code_sent": False,
                "credentials_sent": False,
                "ai_authority": "advisory-only",
                "human_verification_required": True,
                "output_schema_validation": (
                    "failed-local-guardrails"
                ),
                "validation_errors": (
                    validation_errors
                ),
                "generated_at": utc_now(),
            }

            write_artifacts(
                report_path,
                metadata_path,
                structured_path,
                evidence_dir,
                (
                    "# AI Security Analysis\n\n"
                    "AI output was rejected by "
                    "local validation guardrails.\n\n"
                    "Review E017 metadata.\n"
                ),
                metadata,
                {
                    "status": "rejected",
                    "validation_errors": (
                        validation_errors
                    ),
                },
            )

            print(
                "[Project25] AI output rejected "
                "by local guardrails."
            )
            return

        # -----------------------------------------------------
        # Generate human-readable report
        # -----------------------------------------------------

        report_text = render_markdown(
            ai_output,
            deterministic_score,
        )

        metadata = {
            "evidence_id": "E017",
            "status": "completed",
            "provider": "Gemini",
            "model": model,
            "input": (
                "E014 local analysis summary only"
            ),
            "input_sha256": input_sha256,
            "input_evidence": [
                "E014",
            ],
            "raw_scanner_output_sent": False,
            "raw_source_code_sent": False,
            "credentials_sent": False,
            "external_data_sent": True,
            "ai_authority": "advisory-only",
            "human_verification_required": True,
            "output_schema_validation": "passed",
            "evidence_reference_validation": (
                "passed"
            ),
            "generated_at": utc_now(),
        }

        write_artifacts(
            report_path,
            metadata_path,
            structured_path,
            evidence_dir,
            report_text,
            metadata,
            ai_output,
        )

        print(
            "[Project25] AI analysis completed."
        )
        print(
            f"[Project25] Generated {report_path}"
        )
        print(
            f"[Project25] Generated {metadata_path}"
        )
        print(
            f"[Project25] Generated {structured_path}"
        )

    # ---------------------------------------------------------
    # HTTP/API errors
    # ---------------------------------------------------------

    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode(
            "utf-8",
            errors="replace",
        )

        try:
            api_message = (
                json.loads(error_body)
                .get("error", {})
                .get(
                    "message",
                    error_body[:1000],
                )
            )

        except json.JSONDecodeError:
            api_message = error_body[:1000]

        metadata = {
            "evidence_id": "E017",
            "status": "error",
            "provider": "Gemini",
            "model": model,
            "http_status": exc.code,
            "api_error": api_message,
            "input_sha256": input_sha256,
            "external_data_sent": True,
            "raw_scanner_output_sent": False,
            "raw_source_code_sent": False,
            "credentials_sent": False,
            "generated_at": utc_now(),
        }

        write_artifacts(
            report_path,
            metadata_path,
            structured_path,
            evidence_dir,
            (
                "# AI Security Analysis\n\n"
                "Gemini request failed. "
                "Review E017 metadata.\n"
            ),
            metadata,
            {
                "status": "error",
                "http_status": exc.code,
            },
        )

        print(
            f"[Project25] Gemini HTTP error: "
            f"{exc.code}"
        )

    # ---------------------------------------------------------
    # Network / response errors
    # ---------------------------------------------------------

    except (
        urllib.error.URLError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        metadata = {
            "evidence_id": "E017",
            "status": "error",
            "provider": "Gemini",
            "model": model,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "input_sha256": input_sha256,
            "external_data_sent": True,
            "raw_scanner_output_sent": False,
            "raw_source_code_sent": False,
            "credentials_sent": False,
            "generated_at": utc_now(),
        }

        write_artifacts(
            report_path,
            metadata_path,
            structured_path,
            evidence_dir,
            (
                "# AI Security Analysis\n\n"
                "Gemini analysis failed. "
                "Review E017 metadata.\n"
            ),
            metadata,
            {
                "status": "error",
                "error_type": type(exc).__name__,
            },
        )

        print(
            "[Project25] AI analysis error: "
            f"{type(exc).__name__}: {exc}"
        )


if __name__ == "__main__":
    main()