import json
import subprocess
import sys

from secureflow.cli import main
from tests.conftest import FIXTURES


def test_report_writes_all_outputs(tmp_path, capsys):
    req = tmp_path / "requirements.txt"
    req.write_text("flask==2.0.1\n")
    rc = main(["report", "--bandit", str(FIXTURES / "bandit.json"), "--semgrep", str(FIXTURES / "semgrep.json"),
               "--gitleaks", str(FIXTURES / "gitleaks.json"), "--pip-audit", f"{FIXTURES / 'pip-audit.json'}:{req}",
               "--markdown", str(tmp_path / "r.md"), "--sarif", str(tmp_path / "r.sarif"),
               "--json", str(tmp_path / "f.json"), "--commit", "deadbeef", "--paths", "samples", "--fail-on", "critical"])
    assert rc == 0
    out = capsys.readouterr().out
    assert int(out.split()[0]) >= 35 and "5 critical" in out and "gate critical: FAIL, 5 at or above" in out
    md = (tmp_path / "r.md").read_text()
    assert "## Secrets · gitleaks (5)" in md and "## Python static analysis · bandit (20)" in md
    sarif = json.loads((tmp_path / "r.sarif").read_text())
    assert len(sarif["runs"]) == 4
    doc = json.loads((tmp_path / "f.json").read_text())
    assert doc["tools_run"] == ["gitleaks", "bandit", "semgrep", "pip-audit"] and doc["counts"]["critical"] == 5


def test_report_with_missing_scanner_output_means_zero(tmp_path, capsys):
    rc = main(["report", "--bandit", str(tmp_path / "absent.json"), "--json", str(tmp_path / "f.json")])
    assert rc == 0 and "0 findings" in capsys.readouterr().out
    assert json.loads((tmp_path / "f.json").read_text())["tools_run"] == ["bandit"]


def test_gate(tmp_path, capsys):
    main(["report", "--bandit", str(FIXTURES / "bandit.json"), "--json", str(tmp_path / "f.json")])
    assert main(["gate", str(tmp_path / "f.json"), "--fail-on", "critical"]) == 0
    assert "PASS" in capsys.readouterr().out
    assert main(["gate", str(tmp_path / "f.json"), "--fail-on", "high"]) == 1
    out = capsys.readouterr().out
    assert "FAIL, 5 finding(s)" in out and "B602" in out
    assert main(["gate", str(tmp_path / "f.json"), "--fail-on", "none"]) == 0


def test_errors(tmp_path, capsys):
    assert main(["report", "--markdown", str(tmp_path / "r.md")]) == 2           # no scanner given
    bad = tmp_path / "bad.json"
    bad.write_text("{")
    assert main(["report", "--bandit", str(bad)]) == 2
    assert main(["gate", str(tmp_path / "missing.json")]) == 2
    assert capsys.readouterr().err.count("error:") == 3


def test_module_entry_point():
    r = subprocess.run([sys.executable, "-m", "secureflow.cli", "--version"], capture_output=True, text=True)
    assert r.returncode == 0 and "secureflow 0." in r.stdout
