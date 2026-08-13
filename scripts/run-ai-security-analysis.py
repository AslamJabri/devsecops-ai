#!/usr/bin/env python3
"""Project 25 opt-in AI analysis. Sends E014 only, never raw scan output."""

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def write_artifacts(report_path, metadata_path, evidence_dir, report_text, metadata):
    report_path.write_text(report_text, encoding="utf-8")
    metadata_path.write_text(
        json.dumps(metadata, indent=2) + "\n",
        encoding="utf-8",
    )

    for path in (report_path, metadata_path):
        (evidence_dir / path.name).write_bytes(path.read_bytes())


def main():
    analysis_dir = Path(
        sys.argv[1] if len(sys.argv) > 1 else "analysis-results"
    )
    evidence_dir = Path(
        sys.argv[2] if len(sys.argv) > 2 else "/opt/project25/evidence/generated"
    )

    analysis_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    report_path = analysis_dir / "E016-ai-security-analysis.md"
    metadata_path = analysis_dir / "E017-ai-analysis-metadata.json"
    summary_path = analysis_dir / "E014-local-analysis-summary.json"

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    model = os.environ.get("PROJECT25_AI_MODEL", "gpt-5").strip()

    if not api_key:
        write_artifacts(
            report_path,
            metadata_path,
            evidence_dir,
            "# AI Security Analysis\n\nSkipped: no API key configured.\n",
            {
                "evidence_id": "E017",
                "status": "skipped",
                "reason": "OPENAI_API_KEY is not configured",
                "external_data_sent": False,
            },
        )
        return

    try:
        evidence = json.loads(summary_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        write_artifacts(
            report_path,
            metadata_path,
            evidence_dir,
            "# AI Security Analysis\n\nSkipped: E014 evidence summary is unavailable.\n",
            {
                "evidence_id": "E017",
                "status": "error",
                "error_type": type(exc).__name__,
                "external_data_sent": False,
            },
        )
        return

    instructions = """You are the AI security-analysis layer for a local,
evidence-led DevSecOps assessment.

Use only the supplied E014 summary. Do not invent facts, CVEs, scanner results,
ATT&CK techniques, or D3FEND controls. Clearly label inferences as candidate
recommendations. A vulnerability finding alone does not prove attacker activity.

Return a concise Markdown report with:
1. Executive summary
2. Evidence-based findings, each referencing E00X evidence IDs
3. Prioritized remediation or validation actions
4. Candidate MITRE ATT&CK and D3FEND mappings, explicitly marked
   'human verification required'
5. A statement that DAST is deferred to authorized staging.
"""

    payload = {
        "model": model,
        "store": False,
        "instructions": instructions,
        "input": json.dumps(evidence, indent=2),
    }

    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            result = json.loads(response.read().decode("utf-8"))

        output_text = result.get("output_text", "").strip()
        if not output_text:
            output_text = "No text output was returned by the AI service."

        write_artifacts(
            report_path,
            metadata_path,
            evidence_dir,
            "# AI Security Analysis — Human Review Required\n\n"
            + output_text
            + "\n",
            {
                "evidence_id": "E017",
                "status": "completed",
                "model": model,
                "input": "E014 local analysis summary only",
                "raw_source_or_credentials_sent": False,
                "external_data_sent": True,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
        )

    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")

        try:
            api_message = json.loads(error_body).get("error", {}).get(
                "message", error_body[:500]
            )
        except json.JSONDecodeError:
            api_message = error_body[:500]

        write_artifacts(
            report_path,
            metadata_path,
            evidence_dir,
            "# AI Security Analysis\n\nAI request failed. Review E017 metadata.\n",
            {
                "evidence_id": "E017",
                "status": "error",
                "http_status": exc.code,
                "api_error": api_message,
                "external_data_sent": True,
            },
        )

    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        write_artifacts(
            report_path,
            metadata_path,
            evidence_dir,
            "# AI Security Analysis\n\nAI request failed. Review E017 metadata.\n",
            {
                "evidence_id": "E017",
                "status": "error",
                "error_type": type(exc).__name__,
                "external_data_sent": True,
            },
        )


if __name__ == "__main__":
    main()