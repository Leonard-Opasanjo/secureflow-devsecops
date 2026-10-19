"""Integration: the real scanners must flag the vulnerable sample and pass the fixed one."""

import json
import shutil
import subprocess
import sys

import pytest

from secureflow.parsers import parse_bandit, parse_gitleaks, parse_pip_audit, parse_semgrep
from secureflow.report import counts, dedupe
from tests.conftest import ROOT

VULN = ROOT / "samples/vulnerable-app"
FIXED = ROOT / "samples/fixed-app"
SEMGREP_CONFIG = ("p/ci", "p/security-audit")
needs = pytest.mark.skipif


def run(cmd, out):
    subprocess.run(cmd, cwd=ROOT, check=False, capture_output=True, text=True)
    return json.loads(out.read_text()) if out.exists() and out.stat().st_size else None


def test_bandit_on_samples(tmp_path):
    vuln = parse_bandit(run([sys.executable, "-m", "bandit", "-q", "-r", str(VULN), "-f", "json", "-o", str(tmp_path / "v.json"), "--exit-zero"], tmp_path / "v.json"))
    fixed = parse_bandit(run([sys.executable, "-m", "bandit", "-q", "-r", str(FIXED), "-f", "json", "-o", str(tmp_path / "f.json"), "--exit-zero"], tmp_path / "f.json"))
    assert counts(vuln)["high"] >= 5 and len(vuln) >= 15
    assert {f.rule_id for f in vuln} >= {"B602", "B608", "B324", "B301", "B506", "B307", "B501", "B201", "B105"}
    assert fixed == []


@needs(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_semgrep_on_samples(tmp_path):
    base = ["semgrep", "scan", *(a for c in SEMGREP_CONFIG for a in ("--config", c)), "--json", "--metrics=off", "--quiet", "--output"]
    vuln = parse_semgrep(run(base + [str(tmp_path / "v.json"), str(VULN)], tmp_path / "v.json"))
    fixed = parse_semgrep(run(base + [str(tmp_path / "f.json"), str(FIXED)], tmp_path / "f.json"))
    assert len(vuln) >= 11 and any(f.rule_id.endswith("subprocess-injection") and f.severity == "high" for f in vuln)
    assert {f.rule_id.rsplit(".", 1)[-1] for f in vuln} >= {"eval-detected", "avoid-pickle", "avoid-pyyaml-load", "disabled-cert-validation"}
    assert fixed == []


@needs(shutil.which("gitleaks") is None, reason="gitleaks not installed")
def test_gitleaks_on_samples(tmp_path):
    base = ["gitleaks", "dir", "--redact", "--exit-code", "0", "--report-format", "json", "--report-path"]
    vuln = parse_gitleaks(run(base + [str(tmp_path / "v.json"), str(VULN)], tmp_path / "v.json"))
    fixed = parse_gitleaks(run(base + [str(tmp_path / "f.json"), str(FIXED)], tmp_path / "f.json"))
    assert {f.rule_id for f in vuln} >= {"github-pat", "slack-webhook-url", "jwt", "private-key", "generic-api-key"}
    assert all("REDACTED" in f.description for f in vuln)
    assert fixed == []


@needs(shutil.which("pip-audit") is None, reason="pip-audit not installed")
def test_pip_audit_on_samples(tmp_path):
    base = ["pip-audit", "--no-deps", "--disable-pip", "-f", "json", "-r"]
    vuln = dedupe(parse_pip_audit(run(base + [str(VULN / "requirements.txt"), "-o", str(tmp_path / "v.json")], tmp_path / "v.json"), [VULN / "requirements.txt"]))
    fixed = parse_pip_audit(run(base + [str(FIXED / "requirements.txt"), "-o", str(tmp_path / "f.json")], tmp_path / "f.json"), [FIXED / "requirements.txt"])
    assert len(vuln) >= 10 and {f.title.split()[0] for f in vuln} >= {"flask", "werkzeug", "requests", "urllib3"}
    assert all(f.line > 0 for f in vuln)  # every pinned package is pointed at its requirements line
    assert fixed == []
