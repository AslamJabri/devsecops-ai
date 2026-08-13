# Local assessment stage

The Jenkins job now assesses only the checked-out Project 25 repository with three non-invasive tools:

| Evidence | Tool | Check | Baseline behavior |
| --- | --- | --- | --- |
| E004 | Gitleaks | Exposed secrets in repository files | Record results; do not block the baseline build |
| E005 | Bandit | Python static-analysis observations in `demo-app/` | Record results; do not block the baseline build |
| E006 | pip-audit | Known issues in declared Python dependencies | Record results; do not block the baseline build |
| E007 | Shell wrapper | Each scanner's exit code | Supports repeatable before/after comparison |
| E008 | Docker | Built local image metadata | Record image identity for repeatability |
| E009 | Trivy | Known vulnerabilities in the built image | Record results; do not block the baseline build |
| E010 | Shell wrapper | Docker build/inspect and Trivy exit codes | Supports repeatable before/after comparison |

All scans are local to the Jenkins workspace. Gitleaks redacts any matched value in its report. The pipeline records tool output first; mitigation policy gates are deliberately deferred to the Validate phase. An exit code of `1` in E007 can mean a scanner found a review item; read the matching E004–E006 report before making a conclusion.

## Live-demo flow

1. Build the updated Jenkins image.
2. Run **Project 25 - Baseline Evidence**.
3. Open the archived `scan-results/` artifacts and the local `evidence/generated/` folder.
4. Treat scanner output as evidence for human analysis, not an automatic conclusion or ATT&CK claim.

## Container scan boundary

The Jenkins container is given the local Docker Desktop socket only for this lab's build-and-scan stage. It builds `project25-demo-app:<build number>` from `demo-app/`, scans it locally with Trivy, and does not push it to any registry. This is privileged local-lab access; do not use this Compose configuration for a shared or production Jenkins server. The Docker image pins Trivy to a published release so the demo remains reproducible.
