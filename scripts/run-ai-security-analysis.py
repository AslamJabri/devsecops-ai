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
    return datetime.now(timezone.utc).isoformat()


def canonical_json(data: Any) -> str:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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
            (evidence_dir / path.name).write_bytes(path.read_bytes())


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

    content = candidates[0].get("content") or {}
    parts = content.get("parts") or []

    return "".join(
        part.get("text", "") for part in parts if isinstance(part, dict)
    ).strip()


def extract_finish_reason(
    result: dict[str, Any],
) -> str | None:
    candidates = result.get("candidates") or []

    if not candidates:
        return None

    return candidates[0].get("finishReason")


# ---------------------------------------------------------
# Structured-output schema (Constrained Fix 4 & 5)
# ---------------------------------------------------------


AI_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": {
            "type": "string",
            "maxLength": 1200,
        },
        "findings": {
            "type": "array",
            "maxItems": 5,
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "maxLength": 100,
                    },
                    "title": {
                        "type": "string",
                        "maxLength": 200,
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
                        "maxLength": 800,
                    },
                    "root_cause_candidate": {
                        "type": "string",
                        "maxLength": 500,
                    },
                    "remediation": {
                        "type": "array",
                        "maxItems": 5,
                        "items": {
                            "type": "string",
                            "maxLength": 300,
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
            "maxItems": 3,
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
                        "maxLength": 800,
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
            "maxItems": 3,
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
                        "maxLength": 50,
                    },
                    "technique_name": {
                        "type": [
                            "string",
                            "null",
                        ],
                        "maxLength": 100,
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
                        "maxLength": 500,
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
            "maxItems": 5,
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
                        "maxLength": 200,
                    },
                    "status": {
                        "type": "string",
                        "maxLength": 100,
                    },
                    "reason": {
                        "type": "string",
                        "maxLength": 500,
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
            "maxItems": 7,
            "items": {
                "type": "string",
                "maxLength": 300,
            },
        },
        "limitations": {
            "type": "array",
            "maxItems": 5,
            "items": {
                "type": "string",
                "maxLength": 300,
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
            errors.append(f"{section} must be a list")
            continue

        for index, row in enumerate(rows):
            evidence_ids = (
                row.get("evidence_ids", []) if isinstance(row, dict) else []
            )

            if not evidence_ids:
                errors.append(f"{section}[{index}] contains no evidence IDs")
                continue

            for evidence_id in evidence_ids:
                if (
                    not isinstance(evidence_id, str)
                    or evidence_id not in allowed_evidence_ids
                ):
                    errors.append(
                        f"{section}[{index}] references unknown evidence ID {evidence_id}"
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
                "MITRE candidate omitted required human verification flag"
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
                "D3FEND candidate omitted required human verification flag"
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

    lines.append("# AI Security Analysis — Human Review Required")
    lines.append("")

    lines.append("## Deterministic Risk Context")
    lines.append("")

    lines.append(
        f"- Score: {deterministic_risk_score.get('score', 'unknown')}/100"
    )

    lines.append(
        f"- Rating: {deterministic_risk_score.get('rating', 'unknown')}"
    )

    lines.append(
        "- Authority: deterministic local analysis; AI cannot modify this score."
    )
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")

    lines.append(
        ai_output.get(
            "executive_summary",
            "No executive summary returned.",
        )
    )
    lines.append("")

    lines.append("## Evidence-Based Findings")
    lines.append("")

    findings = ai_output.get(
        "findings",
        [],
    )

    if not findings:
        lines.append("No AI findings were generated.")
        lines.append("")

    for finding in findings:
        lines.append(
            f"### {finding.get('finding_id')} — {finding.get('title')}"
        )
        lines.append("")

        lines.append(f"- Priority: {finding.get('priority')}")
        lines.append(f"- Confidence: {finding.get('confidence')}")
        lines.append(
            "- Evidence: " + ", ".join(finding.get("evidence_ids", []))
        )
        lines.append("")

        lines.append(finding.get("analysis", ""))
        lines.append("")

        lines.append(
            "**Root-cause candidate:** "
            + finding.get("root_cause_candidate", "")
        )
        lines.append("")

        remediation = finding.get(
            "remediation",
            [],
        )

        if remediation:
            lines.append("**Recommended remediation:**")

            for item in remediation:
                lines.append(f"- {item}")

            lines.append("")

    lines.append("## Correlations")
    lines.append("")

    correlations = ai_output.get(
        "correlations",
        [],
    )

    if not correlations:
        lines.append("No evidence correlations were proposed.")
        lines.append("")

    for correlation in correlations:
        lines.append(
            "- Evidence "
            + ", ".join(correlation.get("evidence_ids", []))
            + f" — confidence {correlation.get('confidence')}"
        )

        lines.append(f"  {correlation.get('analysis', '')}")

    lines.append("")

    lines.append("## MITRE ATT&CK Candidates")
    lines.append("")

    mitre = ai_output.get(
        "mitre_candidates",
        [],
    )

    if not mitre:
        lines.append("No ATT&CK candidates proposed.")

    for candidate in mitre:
        technique = candidate.get("technique_id") or "No technique assigned"
        technique_name = candidate.get("technique_name") or ""

        lines.append(f"- {technique} {technique_name}".rstrip())
        lines.append(
            "  - Evidence: " + ", ".join(candidate.get("evidence_ids", []))
        )
        lines.append(f"  - Status: {candidate.get('status')}")
        lines.append(f"  - Reason: {candidate.get('reason')}")
        lines.append("  - Human verification required: yes")

    lines.append("")

    lines.append("## D3FEND Candidates")
    lines.append("")

    d3fend = ai_output.get(
        "d3fend_candidates",
        [],
    )

    if not d3fend:
        lines.append("No D3FEND candidates proposed.")

    for candidate in d3fend:
        lines.append(f"- {candidate.get('control')}")
        lines.append(
            "  - Evidence: " + ", ".join(candidate.get("evidence_ids", []))
        )
        lines.append(f"  - Reason: {candidate.get('reason')}")
        lines.append("  - Human verification required: yes")

    lines.append("")

    lines.append("## Recommended Actions")
    lines.append("")

    for action in ai_output.get(
        "recommended_actions",
        [],
    ):
        lines.append(f"- {action}")

    lines.append("")

    lines.append("## Limitations")
    lines.append("")

    for limitation in ai_output.get(
        "limitations",
        [],
    ):
        lines.append(f"- {limitation}")

    lines.append("")
    lines.append("DAST remains deferred to an explicitly authorized staging target.")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------


def main() -> None:
    analysis_dir = Path(
        sys.argv[1] if len(sys.argv) > 1 else "analysis-results"
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

    summary_path = analysis_dir / "E014-local-analysis-summary.json"
    report_path = analysis_dir / "E016-ai-security-analysis.md"
    metadata_path = analysis_dir / "E017-ai-analysis-metadata.json"
    structured_path = analysis_dir / "E018-ai-security-analysis.json"
    debug_api_path = analysis_dir / "E018-gemini-api-response.json"

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
            "reason": "GEMINI_API_KEY is not configured",
            "external_data_sent": False,
            "ai_authority": "advisory-only",
            "human_verification_required": True,
            "generated_at": utc_now(),
        }

        structured_output = {
            "status": "skipped",
            "reason": "GEMINI_API_KEY is not configured",
        }

        write_artifacts(
            report_path,
            metadata_path,
            structured_path,
            evidence_dir,
            (
                "# AI Security Analysis\n\n"
                "Skipped: GEMINI_API_KEY is not configured.\n"
            ),
            metadata,
            structured_output,
        )

        print("[Project25] AI analysis skipped: GEMINI_API_KEY not configured.")
        return

    # ---------------------------------------------------------
    # Read E014
    # ---------------------------------------------------------

    try:
        evidence = json.loads(summary_path.read_text(encoding="utf-8"))

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
                "Skipped: E014 evidence summary is unavailable or invalid.\n"
            ),
            metadata,
            {
                "status": "error",
                "reason": "E014 evidence summary unavailable or invalid",
            },
        )
        return

    # ---------------------------------------------------------
    # Integrity metadata
    # ---------------------------------------------------------

    evidence_json = canonical_json(evidence)
    input_sha256 = sha256_text(evidence_json)

    allowed_evidence_ids = set(evidence.get("source_evidence", []))
    deterministic_score = evidence.get("risk_score", {})

    # ---------------------------------------------------------
    # System instruction (Fix 3: Concise limits)
    # ---------------------------------------------------------

    instructions = """
You are the advisory AI security-analysis layer for Project 25,
a controlled local DevSecOps security assessment.

Use only the supplied E014 evidence packet.

STRICT RULES:
1. Never invent evidence IDs, vulnerabilities, CVEs, scanner results,
   source-code facts, exploitability, credentials, attacker behavior,
   ATT&CK techniques, or D3FEND techniques.
2. Scanner observations do not prove attacker activity.
3. Every analysis object must reference supplied evidence IDs.
4. Do not modify, reinterpret, replace or recalculate the
   deterministic risk score supplied by E014.
5. ATT&CK and D3FEND candidates require human verification.
6. AI recommendations are advisory only.
7. Production approval, IAM changes, deployment, credential
   rotation and security-policy changes require human control.
8. DAST remains deferred to an explicitly authorized staging environment.

Be concise. Do not repeat every individual vulnerability.
Summarize scanner categories and significant severity counts.

Generate at most:
- 5 findings
- 3 correlations
- 3 MITRE candidates
- 5 D3FEND/control candidates
- 7 recommended actions
- 5 limitations

Keep each analysis or reason under 300 characters.
Keep each remediation item under 180 characters.
"""

    user_prompt = (
        "Analyze the following Project 25 E014 evidence summary.\n\n"
        + json.dumps(
            evidence,
            indent=2,
            ensure_ascii=False,
        )
    )

    # ---------------------------------------------------------
    # Gemini payload (Fix 1: maxOutputTokens = 8192)
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
            "maxOutputTokens": 8192,
            "responseMimeType": "application/json",
            "responseJsonSchema": AI_RESPONSE_SCHEMA,
        },
    }

    endpoint = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        + urllib.parse.quote(model, safe="")
        + ":generateContent"
    )

    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
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
        with urllib.request.urlopen(request, timeout=90) as response:
            result = json.loads(response.read().decode("utf-8"))

        # Fix 6: Save raw API response for debugging/audit
        write_json(debug_api_path, result)
        copy_to_evidence([debug_api_path], evidence_dir)

        # Fix 2: Extract finishReason
        finish_reason = extract_finish_reason(result)

        if finish_reason == "MAX_TOKENS":
            metadata = {
                "evidence_id": "E017",
                "status": "error",
                "provider": "Gemini",
                "model": model,
                "finish_reason": finish_reason,
                "error": "Structured response was truncated due to output token limit",
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
                    "Error: Gemini response was truncated because the output token limit was reached.\n"
                    "Review E017 metadata.\n"
                ),
                metadata,
                {
                    "status": "error",
                    "finish_reason": finish_reason,
                    "reason": "Structured response was truncated",
                },
            )

            print(
                "[Project25] AI analysis error: Response truncated (MAX_TOKENS)."
            )
            return

        output_text = extract_candidate_text(result)

        if not output_text:
            raise ValueError("Gemini returned no text output")

        # -----------------------------------------------------
        # Parse structured output (Fix 7: E018-debug-invalid-response.txt)
        # -----------------------------------------------------

        try:
            ai_output = json.loads(output_text)

        except json.JSONDecodeError as exc:
            debug_path = analysis_dir / "E018-debug-invalid-response.txt"
            debug_path.write_text(output_text + "\n", encoding="utf-8")
            (evidence_dir / debug_path.name).write_bytes(
                debug_path.read_bytes()
            )

            metadata = {
                "evidence_id": "E017",
                "status": "error",
                "provider": "Gemini",
                "model": model,
                "finish_reason": finish_reason,
                "error": "Gemini returned invalid JSON",
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
                    "Error: Gemini returned invalid JSON.\n"
                    "Raw response saved to E018-debug-invalid-response.txt.\n"
                    "Review E017 metadata.\n"
                ),
                metadata,
                {
                    "status": "error",
                    "finish_reason": finish_reason,
                    "reason": "Gemini returned invalid JSON",
                },
            )

            print("[Project25] AI analysis error: Invalid JSON returned.")
            return

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

        validation_errors.extend(validate_ai_authority(ai_output))

        if validation_errors:
            metadata = {
                "evidence_id": "E017",
                "status": "rejected",
                "provider": "Gemini",
                "model": model,
                "finish_reason": finish_reason,
                "input": "E014 local analysis summary only",
                "input_sha256": input_sha256,
                "external_data_sent": True,
                "raw_scanner_output_sent": False,
                "raw_source_code_sent": False,
                "credentials_sent": False,
                "ai_authority": "advisory-only",
                "human_verification_required": True,
                "output_schema_validation": "failed-local-guardrails",
                "validation_errors": validation_errors,
                "generated_at": utc_now(),
            }

            write_artifacts(
                report_path,
                metadata_path,
                structured_path,
                evidence_dir,
                (
                    "# AI Security Analysis\n\n"
                    "AI output was rejected by local validation guardrails.\n\n"
                    "Review E017 metadata.\n"
                ),
                metadata,
                {
                    "status": "rejected",
                    "validation_errors": validation_errors,
                },
            )

            print("[Project25] AI output rejected by local guardrails.")
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
            "finish_reason": finish_reason,
            "input": "E014 local analysis summary only",
            "input_sha256": input_sha256,
            "input_evidence": ["E014"],
            "raw_scanner_output_sent": False,
            "raw_source_code_sent": False,
            "credentials_sent": False,
            "external_data_sent": True,
            "ai_authority": "advisory-only",
            "human_verification_required": True,
            "output_schema_validation": "passed",
            "evidence_reference_validation": "passed",
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

        print("[Project25] AI analysis completed.")
        print(f"[Project25] Generated {report_path}")
        print(f"[Project25] Generated {metadata_path}")
        print(f"[Project25] Generated {structured_path}")

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
                "Gemini request failed. Review E017 metadata.\n"
            ),
            metadata,
            {
                "status": "error",
                "http_status": exc.code,
            },
        )

        print(f"[Project25] Gemini HTTP error: {exc.code}")

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
                "Gemini analysis failed. Review E017 metadata.\n"
            ),
            metadata,
            {
                "status": "error",
                "error_type": type(exc).__name__,
            },
        )

        print(f"[Project25] AI analysis error: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()