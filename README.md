# DevShield AI — Local DevSecOps Assessment Lab

A small, reproducible macOS-friendly local lab for an evidence-led Jenkins DevSecOps security assessment. The initial release is deliberately limited to bootable infrastructure and safe baseline evidence; scanners, AI analysis, and mitigations are added only after this foundation is verified.

## What starts

- **Jenkins** at `http://localhost:8080` (or `JENKINS_HTTP_PORT`)
- **Demo application** at `http://localhost:5001` (or `DEMO_APP_PORT`)
- A pre-created Jenkins job: **DevShield AI - Evidence Assessment**, which clones one repository you explicitly authorize for assessment

The job clones the repository configured as its authorized target, creates a fingerprinted evidence bundle, and does not run exploit code.

Set `DEVSHIELD_TARGET_GIT_URL`, `DEVSHIELD_TARGET_GIT_BRANCH`, and `DEVSHIELD_AUTHORIZATION_ACK=I_HAVE_PERMISSION` in `.env`. The acknowledgment is required before the job will clone a target. For a private repository, create a Jenkins credential and set only its ID in `DEVSHIELD_TARGET_GIT_CREDENTIALS_ID`; never put a token in `.env`.

The assessment stages run Gitleaks, Bandit, and pip-audit against the authorized repository, then build its container image when it contains a Dockerfile and scan it with Trivy. They archive evidence for deterministic analysis and advisory Gemini insight. DAST is deliberately deferred to an authorized staging deployment. See [the assessment notes](docs/assessment-stage.md).

The Jenkins image includes a pinned Docker command-line client and uses Docker Desktop through the local socket mount only for the container assessment stage.

## Run it on macOS

Prerequisite: [Docker Desktop for Mac](https://www.docker.com/products/docker-desktop/) must be running, with at least 4 GB memory allocated.

```sh
cp .env.example .env
docker compose up --build -d
docker compose ps
```

Open Jenkins and sign in with the values in your local `.env` file. Then open **DevShield AI - Evidence Assessment**, choose **Build Now**, and inspect the archived artifacts. The same files are available locally in `evidence/generated/`.

Check the demo service:

```sh
curl http://localhost:5001/health
```

Stop the lab while retaining Jenkins data:

```sh
docker compose down
```

For a completely fresh lab state, first stop it, then run `docker compose down -v`. This removes the Jenkins volume and its build history.

## Repository map

`baseline/` contains fictional observations; `demo-app/` contains the harmless app and baseline Jenkinsfile; `jenkins/` contains the Jenkins image and configuration; and `evidence/` holds generated evidence (ignored by Git).

## Safety and assessment order

This lab follows the project lifecycle: Plan → Build → Baseline → Assess/Simulate → Evidence → Analyze → ATT&CK/D3FEND mapping → Mitigate → Validate → Document → Present. See [the lifecycle checklist](docs/project-lifecycle.md) for the current stage.

Do not put real passwords, tokens, private repositories, or production endpoints into this lab. Use dummy data only. The default local password exists solely to make the first demo reproducible; replace it in `.env` before any screen recording or shared demo.
