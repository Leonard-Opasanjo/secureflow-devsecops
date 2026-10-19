# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:
<https://github.com/Leonard-Opasanjo/secureflow-devsecops/security/advisories/new>.
Describe the scenario, the workflow inputs involved and how to reproduce it. You should hear back within seven
days.

## What is in scope

SecureFlow runs on every pull request to the repositories that adopt it, so its own attack surface matters.
These would be vulnerabilities in this project:

- A way for a pull request's content (file names, file contents, commit messages, branch names) to execute
  commands in the workflow, alter the gate result, or write outside the runner.
- A way for scanner output or scanned files to inject HTML, Markdown or links into the report that would
  mislead a reviewer, or to break the SARIF so alerts are hidden.
- A secret value reaching the job log, the artifact, the pull request comment or the SARIF despite `--redact`.
- A dependency download that is not pinned and verified.
- A permission the workflow requests that it does not need.

## What is not

- Findings the scanners miss. SecureFlow is a pipeline around Bandit, Semgrep, Gitleaks and pip-audit; report
  false negatives to those projects. The remediation guide documents one such gap deliberately.
- The planted flaws in `samples/vulnerable-app`. They are the test material.
- A caller granting more permissions than the documented three.

## Operational notes

- Pin the reusable workflow to a tag or commit rather than `@main` once adopted.
- The Gitleaks binary is verified against a SHA-256 recorded in the workflow; when updating the version, take the
  checksum from the release's `_checksums.txt`.
- pip-audit resolves dependencies by downloading packages named in `requirements*.txt`. Treat a requirements
  file in a pull request as untrusted input to that step.
