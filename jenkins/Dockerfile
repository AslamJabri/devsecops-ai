FROM jenkins/jenkins:lts-jdk17

USER root
ARG GITLEAKS_VERSION=8.18.1
ARG TRIVY_VERSION=0.70.0
ARG DOCKER_CLI_VERSION=27.3.1

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates git python3-pip python3-venv \
    && pip3 install --no-cache-dir --break-system-packages bandit==1.7.9 pip-audit==2.7.3 \
    && rm -rf /var/lib/apt/lists/*
RUN curl --fail --location --silent --show-error \
      "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_CLI_VERSION}.tgz" \
    | tar --extract --gzip --file - --directory /tmp \
    && install --mode=0755 /tmp/docker/docker /usr/local/bin/docker \
    && docker --version \
    && rm -rf /tmp/docker
RUN curl --fail --location --silent --show-error \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar --extract --gzip --file - --directory /usr/local/bin gitleaks \
    && chmod 0755 /usr/local/bin/gitleaks
RUN curl --fail --location --silent --show-error \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    | tar --extract --gzip --file - --directory /usr/local/bin trivy \
    && chmod 0755 /usr/local/bin/trivy
USER jenkins

# Keep the first lab image focused on pipeline execution and reproducible setup.
COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt
