FROM python:3.12-slim

ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sSL -o /tmp/gitleaks.tgz \
         "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    && echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tgz" | sha256sum -c - \
    && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks && rm /tmp/gitleaks.tgz

# Scanners first, so the heavy layer is cached across changes to the reporter
RUN pip install --no-cache-dir bandit semgrep pip-audit

WORKDIR /opt/secureflow
COPY pyproject.toml README.md LICENSE ./
COPY secureflow ./secureflow
COPY scripts/secureflow-local.sh /usr/local/bin/secureflow-local
RUN pip install --no-cache-dir . && useradd --create-home --uid 1000 scanner
USER scanner
ENV SEMGREP_SEND_METRICS=off

WORKDIR /src
ENTRYPOINT ["secureflow-local"]
