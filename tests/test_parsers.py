import pytest

from secureflow.parsers import load_json, parse_bandit, parse_gitleaks, parse_pip_audit, parse_semgrep


def test_load_json_missing_or_empty_is_none(tmp_path):
    assert load_json(tmp_path / "nope.json") is None
    empty = tmp_path / "empty.json"
    empty.write_text("")
    assert load_json(empty) is None
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_json(bad)


def test_bandit(fixture):
    out = parse_bandit(fixture("bandit.json"))
    assert len(out) == 19 and all(f.tool == "bandit" for f in out)
    shell = next(f for f in out if f.rule_id == "B602")
    assert shell.severity == "high" and shell.file == "samples/vulnerable-app/app.py" and shell.line == 47
    assert shell.cwe == "CWE-78" and shell.url.startswith("https://bandit.readthedocs.io")
    assert "confidence high" in shell.description
    assert {f.severity for f in out} == {"high", "medium", "low"}
    assert parse_bandit(None) == [] and parse_bandit({"results": []}) == []


def test_semgrep(fixture):
    out = parse_semgrep(fixture("semgrep.json"))
    assert len(out) >= 11 and all(f.tool == "semgrep" for f in out)
    assert {f.rule_id.rsplit(".", 1)[-1] for f in out} >= {"subprocess-injection", "eval-detected", "avoid-pickle", "avoid-pyyaml-load", "disabled-cert-validation", "debug-enabled"}
    inj = next(f for f in out if f.rule_id.endswith("subprocess-injection"))
    assert inj.severity == "high" and inj.line == 47 and inj.cwe.startswith("CWE-")
    assert inj.url.startswith("https://semgrep.dev/")
    assert parse_semgrep(None) == []


def test_semgrep_high_impact_warning_becomes_high():
    data = {"results": [{"check_id": "x.rule", "path": "a.py", "start": {"line": 3},
                         "extra": {"message": "m", "severity": "WARNING", "metadata": {"impact": "HIGH", "cwe": ["CWE-89: SQLi"]}}}]}
    (f,) = parse_semgrep(data)
    assert f.severity == "high" and f.cwe == "CWE-89"


def test_gitleaks(fixture):
    out = parse_gitleaks(fixture("gitleaks.json"))
    assert len(out) == 5 and all(f.tool == "gitleaks" and f.severity == "critical" for f in out)
    assert {f.rule_id for f in out} >= {"github-pat", "slack-webhook-url", "jwt", "private-key", "generic-api-key"}
    pat = next(f for f in out if f.rule_id == "github-pat")
    assert pat.file == "samples/vulnerable-app/settings.py" and pat.line == 9
    assert "REDACTED" in pat.description and "working tree" in pat.description
    assert "rotate" in pat.remediation and pat.cwe == "CWE-798"
    assert parse_gitleaks(None) == [] and parse_gitleaks([]) == []


def test_gitleaks_commit_context():
    (f,) = parse_gitleaks([{"RuleID": "r", "File": "a", "StartLine": 2, "Commit": "0123456789", "Date": "2026-10-19T10:00:00Z"}])
    assert "commit 0123456 on 2026-10-19" in f.description


def test_pip_audit_locates_requirement_line(fixture, tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("# pins\nFlask==2.0.1\nrequests==2.25.1\n")
    out = parse_pip_audit(fixture("pip-audit.json"), [req])
    flask = [f for f in out if f.title.startswith("flask 2.0.1")]
    assert flask and all(f.file == str(req) and f.line == 2 for f in flask)
    assert all(f.severity == "high" and f.tool == "pip-audit" for f in out)
    assert any(f.remediation.startswith("Upgrade flask to") for f in flask)
    idna = next(f for f in out if f.title.startswith("idna"))
    assert idna.file == str(req) and idna.line == 0  # transitive: not pinned in the file
    assert idna.url.startswith("https://osv.dev/vulnerability/")


def test_pip_audit_without_requirements(fixture):
    out = parse_pip_audit(fixture("pip-audit.json"))
    assert out and all(f.file == "requirements.txt" and f.line == 0 for f in out)
    assert parse_pip_audit(None) == []
