# Contributing

Bug reports, scanner integrations and sample improvements are welcome.

## Set up

```bash
git clone https://github.com/Leonard-Opasanjo/secureflow-devsecops.git
cd secureflow-devsecops
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

Gitleaks is a Go binary: download the release for your platform from
<https://github.com/gitleaks/gitleaks/releases> (the version pinned in `.github/workflows/secureflow.yml`) and put
it on your `PATH`. The integration tests that need it skip when it is absent.

## Before you open a pull request

```bash
ruff check .
pytest
bandit -q -c pyproject.toml -r secureflow
pip-audit
scripts/secureflow-local.sh .          # the whole pipeline on this repository; the vulnerable sample will fail the gate, as intended
```

## Adding a scanner

1. Write `parse_<tool>(data) -> list[Finding]` in `secureflow/parsers.py`. Map the tool's severity onto the
   SecureFlow scale and say how in the README table. Fill `remediation`, `url` and `cwe` when the tool provides
   them.
2. Add the tool name to `TOOLS` in `findings.py` and a section title to `SECTION` in `report.py`.
3. Add a `--<tool>` option in `cli.py` and include it in `_collect`.
4. Capture real output from the tool against `samples/vulnerable-app` into `tests/fixtures/<tool>.json`
   (redact any secret values) and write parser tests against it. Add the tool to `tests/test_samples.py`.
5. Add a step to `.github/workflows/secureflow.yml` and to `scripts/secureflow-local.sh`, and the install to
   the Dockerfile. Pass inputs through `env:`, never `${{ }}` inside `run:`.
6. Document it in the README.

## Changing the samples

Every change to `samples/vulnerable-app` should add a row to `docs/REMEDIATION.md` and the matching fix to
`samples/fixed-app`. The integration tests assert minimum counts on the vulnerable app and zero findings on the
fixed app; update the expectations and the numbers quoted in the README.

## Updating pinned tools

Gitleaks is pinned by version and SHA-256 in `.github/workflows/secureflow.yml`, `.github/workflows/ci.yml` and
`Dockerfile`. Update all three together; take the checksum from the `_checksums.txt` file of the release.

## Style

`ruff` settings in `pyproject.toml` are the style guide. The reporter has no third-party dependencies and should
stay that way.

## Security issues

See [SECURITY.md](SECURITY.md).
