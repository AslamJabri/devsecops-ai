# Project 25 lifecycle and lab boundary

This repository starts with the **Build** phase of the Project 25 assessment. It is intentionally a small, local-only lab and contains no real secrets, production systems, or exploitation steps.

| Project phase | Current repository support | Next evidence-driven step |
| --- | --- | --- |
| Plan | Scope and boundary in README | Confirm assessment objectives and rules of engagement |
| Build | Docker Compose, Jenkins, demo app | Boot and capture environment evidence |
| Baseline | Simulated findings and baseline Jenkinsfile | Run `sentinelforge-ai-assessment` |
| Assess / Simulate | Local Gitleaks, Bandit, pip-audit, Docker build, Trivy, and passive ZAP scans | Review E004–E013 with human context |
| Evidence | E001–E013 register | Preserve console output and artifacts |
| Analyze | Not yet enabled | Add AI summary over collected evidence, with human review |
| ATT&CK / D3FEND | Not yet mapped | Map only demonstrated observations and mitigations |
| Mitigate / Validate | Not yet enabled | Add controls, rerun the same checks, compare evidence |
| Document / Present | Starter documentation | Produce report, workbook, and live-demo narrative |
| Assess / Simulate | Local Gitleaks, Bandit, pip-audit, Docker build, and Trivy scans | Review E004–E010 with human context; defer DAST to staging |
| Evidence | E001–E010 register | Preserve console output and artifacts |
| Analyze | Local evidence summary (E014) | Optionally enrich the reviewed summary with an AI service later |
| ATT&CK / D3FEND | Human-review candidate worksheet (E015) | Map only demonstrated observations and mitigations |
