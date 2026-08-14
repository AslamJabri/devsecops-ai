# DevShield AI setup and operations guide

DevShield AI is a local, evidence-led DevSecOps assessment lab. It clones one repository selected by the Jenkins operator, runs non-exploitative repository and container checks, records the results as evidence, then creates deterministic and optional AI-assisted analysis.

## 1. What DevShield does

For an explicitly authorized target repository, the Jenkins job performs this flow:

```text
Clone target -> Gitleaks -> Bandit -> pip-audit -> Docker build -> Trivy
             -> evidence bundle -> deterministic analysis -> MITRE/D3FEND worksheet
             -> optional Gemini advisory analysis -> final checksums
```

The job does **not** exploit a target or deploy its image. DAST is intentionally deferred until there is an authorized, reachable staging deployment.

## 2. Requirements

- Docker Desktop running on macOS, with at least 4 GB of memory available.
- Git, to clone DevShield AI and pull updates.
- Internet access for public Git targets, tool vulnerability databases, and optional Gemini analysis.
- A Git credential in Jenkins when the target repository is private.
- Explicit authorization from the repository owner before scanning.

The Jenkins container mounts the local Docker socket to build and inspect a target image. This is appropriate for a local controlled lab only. Do not use this Compose configuration unchanged on a shared Jenkins server or production host.

## 3. Initial setup

Clone DevShield AI, then start it from the repository root:

```sh
cp .env.example .env
docker compose up --build -d
docker compose ps
```

Open `http://localhost:8080` and sign in with `JENKINS_ADMIN_ID` and `JENKINS_ADMIN_PASSWORD` from `.env`.

To stop containers while preserving Jenkins jobs and build history:

```sh
docker compose down
```

Use `docker compose down -v` only when a fully fresh Jenkins state is required. It deletes the Jenkins volume and build history.

## 4. Environment variables

Copy `.env.example` to `.env`. Do not commit `.env`.

| Variable | Required | Purpose |
| --- | --- | --- |
| `JENKINS_ADMIN_ID` | Yes | Initial local Jenkins administrator username. |
| `JENKINS_ADMIN_PASSWORD` | Yes | Initial local Jenkins password. Use a new local-only value. |
| `JENKINS_HTTP_PORT` | No | Host port for Jenkins; default `8080`. |
| `DEVSHIELD_TOOL_GIT_URL` | No | Repository containing DevShield pipeline scripts; default is this repository. |
| `DEVSHIELD_TOOL_GIT_BRANCH` | No | Branch for the DevShield tool repository; default `main`. |
| `GEMINI_API_KEY` | No | Enables advisory Gemini analysis. If absent, all non-AI stages still run. |
| `GEMINI_MODEL` | No | Gemini model name; default is defined in `docker-compose.yml`. |

The target repository URL, branch, credential ID, and authorization acknowledgement are deliberately **not** environment variables. They are provided for each run in Jenkins, preventing a previous target from being silently reused.

## 5. Scan an authorized repository

1. Open **DevShield AI - Evidence Assessment** in Jenkins.
2. Select **Build with Parameters**.
3. Fill in the parameters:

| Parameter | Value |
| --- | --- |
| `TARGET_REPOSITORY_URL` | HTTPS or SSH Git URL of a repository you own or are authorized to assess. |
| `TARGET_BRANCH` | Existing branch name, such as `main` or `master`. |
| `TARGET_CREDENTIALS_ID` | Optional Jenkins credential ID for a private repository. Leave blank for a public repository. |
| `I_HAVE_AUTHORIZATION` | Must be selected before the job will clone the target. |

4. Select **Build** and follow the Console Output.

For a private repository, create a Git credential in **Manage Jenkins -> Credentials** first. Enter its Jenkins credential ID in `TARGET_CREDENTIALS_ID`; never place a personal-access token in a build parameter, repository URL, `.env`, console output, or evidence file.

## 6. Supported target layouts

DevShield scans the repository root.

- Gitleaks examines repository files for potential secrets.
- Bandit recursively examines Python code.
- pip-audit uses `requirements.txt`, or finds a `requirements*.txt` file within three directory levels.
- The container stage looks for a `Dockerfile` at the root or within three directory levels.

A non-Python target can still receive Gitleaks and container scanning. Bandit and pip-audit may return no applicable findings. A target without a Dockerfile produces a recorded skipped container stage; this is not a Jenkins failure.

Building a Dockerfile executes its build instructions. Scan only code you are authorized to handle and trust sufficiently to build in this isolated local lab.

## 7. Evidence and reports

Jenkins archives reports with every build. It also writes a copy to `evidence/generated/` on the host. Evidence IDs make claims traceable to their source.

| Evidence ID | File | Meaning |
| --- | --- | --- |
| E001 | `E001-baseline-scope.txt` | Target URL, branch, and recorded authorization acknowledgement. |
| E002 | `E002-target-commit.txt` | Exact target commit assessed. |
| E003 | `E003-target-file-inventory.txt`, `E003-checksums.sha256` | File inventory and initial evidence integrity checksums. |
| E004 | `E004-gitleaks.json` | Potential secret matches. Treat matches as sensitive and validate them carefully. |
| E005 | `E005-bandit.json` | Python static-analysis observations. |
| E006 | `E006-pip-audit.json` | Known vulnerabilities in declared Python dependencies. |
| E007 | `E007-scan-exit-codes.json` | Exit codes for Gitleaks, Bandit, and pip-audit. |
| E009 | `E009-trivy-image.json` | Container-image vulnerability observations, or a skipped record. |
| E010 | `E010-container-scan-exit-codes.json` | Docker build and Trivy exit codes. |
| E014 | `E014-local-analysis-summary.json` | Deterministic normalization, counts, risk context, and local priority score. |
| E015 | `E015-mitre-d3fend-review-worksheet.json` | Candidate mapping worksheet for human review. |
| E016 | `E016-ai-security-analysis.md` | Optional Gemini advisory report. |
| E017 | `E017-ai-analysis-metadata.json` | AI provider, status, and data-handling metadata. |
| E018 | `E018-ai-security-analysis.json` | Structured AI output after local guardrail checks. |
| E019 | `E019-final-evidence-checksums.sha256` | Checksums for the final evidence set. |
| E020 | `E020-ai-decision-log.json` | AI decision log and review metadata. |

## 8. How to interpret the reports

### Gitleaks (E004)

A match is a potential secret, not automatic proof of exposure. First confirm whether it is an active credential, test fixture, placeholder, or false positive. If active, revoke or rotate it outside the pipeline, remove it from the repository history according to your organization’s process, and rerun the same assessment.

### Bandit (E005)

Read `issue_text`, `issue_severity`, `issue_confidence`, and the affected file/line. Validate exploitability in the application’s real context. A static finding can be safe in a controlled test path, or serious when it handles untrusted input.

### pip-audit (E006)

Review the affected package, installed version, advisory identifier, and available fixed version. Check whether the vulnerable dependency is reachable in the target application before prioritizing it. Update the declared dependency, test the application, and rerun the pipeline to record validation evidence.

### Trivy (E009)

Separate base-image operating-system findings from language-package findings. Review severity, fixed version, installed version, and whether a fix is available. The raw count alone is not business risk: an unreachable package or no-fix base-image finding needs different treatment than a reachable critical dependency with a fixed version.

### Exit codes (E007 and E010)

An exit code of `1` can mean a scanner found observations. It does not mean the Jenkins infrastructure failed. Check the associated JSON report. A Docker build exit code other than `0` means image scanning could not run; correct the Docker build separately.

### Deterministic summary (E014)

Use E014 to prioritize review. Its score is transparent and capped at 100, but it is a local lab aid—not CVSS, a deployment decision, or a substitute for organizational risk acceptance. AI is not allowed to change this score.

### ATT&CK and D3FEND worksheet (E015)

Do not claim an ATT&CK technique merely because a vulnerability exists. Record ATT&CK only when behavior was safely demonstrated in scope or independently supported by evidence. Use D3FEND rows as controls to consider or validate. A human reviewer must approve every mapping.

### Gemini advisory analysis (E016-E020)

Gemini receives E014 only, not raw source code, scanner reports, or credentials. It is advisory-only and may suggest priorities, remediation, and candidate mappings. Confirm every statement against E004-E010 before including it in a report or making a change. If E017 says `skipped`, configure `GEMINI_API_KEY`; if it says `error` or `rejected`, use the metadata and local deterministic reports instead.

## 9. Baseline, mitigation, and validation

For a defensible project demonstration:

1. Run the authorized target and archive the baseline evidence.
2. Choose a confirmed, safe-to-fix observation.
3. Make the remediation in the target repository through its normal review process.
4. Run the identical DevShield parameters again.
5. Compare E002, E005/E006/E009, E014, and E019 before and after.
6. Record the decision, limitation, and result in your documentation.

The goal is evidence-backed improvement, not simply a lower scanner count.

## 10. Common issues

| Symptom | Likely cause and action |
| --- | --- |
| `Select I_HAVE_AUTHORIZATION` | Use **Build with Parameters** and select the authorization checkbox. |
| `Couldn't find any revision to build` | The branch does not exist. Check the repository’s default branch and enter the correct branch name. |
| Private repository clone fails | Create a Jenkins Git credential and enter its credential ID; do not place the token in a parameter. |
| `docker: not found` | Rebuild and recreate the Jenkins container from this repository’s current Docker Compose configuration. |
| Container scan skipped | The target has no Dockerfile, the Dockerfile is deeper than three directories, or the build failed. Review E010 and console output. |
| Gemini analysis skipped | `GEMINI_API_KEY` is not configured; all deterministic reporting remains available. |
| Gemini analysis rejected | Read E017 and E018; local guardrails rejected malformed or unsupported AI output. Use E014/E015 for the human review. |

## 11. Current boundary

DevShield AI is suitable for a controlled local lab, demonstration, and authorized proof of concept. It is not an enterprise deployment. Production hardening would require isolated agents, least-privilege credentials, centralized secrets management, a registry and image-signing policy, SSO/RBAC, retention controls, monitoring, and formal staging/DAST authorization.
