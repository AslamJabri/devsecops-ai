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

Before cloning, the pipeline clears only its own Jenkins workspace. This prevents a stale or incomplete `.git` directory from affecting repeatability; it does not alter the GitHub repository or the persistent evidence folder.
## Deferred DAST

DAST is intentionally deferred. It will be run later against an authorized, reachable staging deployment after the pre-deployment controls have been reviewed. It is not part of the current baseline evidence set.
## Live-demo flow

1. Build the updated Jenkins image.
2. Run **Project 25 - Baseline Evidence**.
3. Open the archived `scan-results/` artifacts and the local `evidence/generated/` folder.
4. Treat scanner output as evidence for human analysis, not an automatic conclusion or ATT&CK claim.

## Container scan boundary

The Jenkins container is given the local Docker Desktop socket only for this lab's build-and-scan stage. It builds `devshield-demo-app:<build number>` from `demo-app/`, scans it locally with Trivy, and does not push it to any registry. This is privileged local-lab access; do not use this Compose configuration for a shared or production Jenkins server. The Docker image pins Trivy to a published release so the demo remains reproducible.

## Passive DAST boundary

The final assessment stage launches OWASP ZAP's baseline scan in a temporary container on the Compose network. Its only target is `http://demo-app:5000`, the local demo service. ZAP's baseline scan spiders the target and reports passive observations; it does not perform active attacks. The temporary container mounts the Jenkins home volume only at ZAP's required report directory, then exits. The ZAP reports are evidence for human review, not automatic vulnerability claims.
