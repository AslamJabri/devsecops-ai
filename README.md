# Project 25 — Local DevSecOps Assessment Lab

A small, reproducible macOS-friendly local lab for an evidence-led Jenkins DevSecOps security assessment. The initial release is deliberately limited to bootable infrastructure and safe baseline evidence; scanners, AI analysis, and mitigations are added only after this foundation is verified.

## What starts

- **Jenkins** at `http://localhost:8080` (or `JENKINS_HTTP_PORT`)
- **Demo application** at `http://localhost:5001` (or `DEMO_APP_PORT`)
- A pre-created Jenkins job: **Project 25 - Baseline Evidence**, which clones the configured GitHub repository's `main` branch

The job copies only fictional observations into a fingerprinted evidence bundle. It does not contact external systems or run exploit code.

The public repository URL and branch are configured in `.env` as `PROJECT25_GIT_URL` and `PROJECT25_GIT_BRANCH`. For a private repository, add a Jenkins credential and update the checkout configuration rather than placing a token in `.env`.

The assessment stages run Gitleaks, Bandit, and pip-audit against the cloned local workspace, then build the local demo image and scan it with Trivy. Finally, OWASP ZAP performs a passive baseline scan against only the internal demo service. They archive E004–E013. See [the assessment notes](docs/assessment-stage.md).

The Jenkins image includes a pinned Docker command-line client and uses Docker Desktop through the local socket mount only for the container assessment stage.

## Run it on macOS

Prerequisite: [Docker Desktop for Mac](https://www.docker.com/products/docker-desktop/) must be running, with at least 4 GB memory allocated.

```sh
cp .env.example .env
docker compose up --build -d
docker compose ps
```

Open Jenkins and sign in with the values in your local `.env` file. Then open **Project 25 - Baseline Evidence**, choose **Build Now**, and inspect the archived `generated/` artifacts. The same files are available locally in `evidence/generated/`.

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
