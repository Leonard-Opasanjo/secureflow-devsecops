import json
from datetime import UTC, datetime

from secureflow.findings import Finding
from secureflow.report import counts, dedupe, from_json, gate, to_json, to_markdown, to_sarif

WHEN = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


def sample():
    return [
        Finding("bandit", "B602", "high", "shell=True | pipe", "app.py", 47, remediation="use a list"),
        Finding("bandit", "B602", "high", "duplicate", "app.py", 47),
        Finding("gitleaks", "github-pat", "critical", "GitHub token", "settings.py", 8, url="", cwe="CWE-798"),
        Finding("pip-audit", "PYSEC-1", "high", "flask", "requirements.txt", 2, url="https://osv.dev/vulnerability/PYSEC-1"),
        Finding("semgrep", "r.debug", "medium", "debug on", "app.py", 94),
        Finding("bandit", "B110", "low", "try/except/pass", "app.py", 90),
    ]


def test_dedupe_orders_by_severity_then_tool():
    out = dedupe(sample())
    assert len(out) == 5
    assert [f.rule_id for f in out] == ["github-pat", "B602", "PYSEC-1", "r.debug", "B110"]
    assert out[1].title == "shell=True | pipe"  # first occurrence wins


def test_counts_and_gate():
    out = dedupe(sample())
    assert counts(out) == {"critical": 1, "high": 2, "medium": 1, "low": 1, "info": 0}
    assert len(gate(out, "high")) == 3 and len(gate(out, "critical")) == 1
    assert gate(out, "none") == [] and len(gate(out, "low")) == 5


def test_markdown():
    md = to_markdown(dedupe(sample()), fail_on="high", commit="0123456789abcdef", paths=".",
                     repo="https://github.com/o/r", generated=WHEN)
    assert md.startswith("# SecureFlow security report")
    assert "**5 findings** · 1 critical · 2 high · 1 medium · 1 low · 0 info" in md
    assert "Gate `high`: **FAIL** (3 at high or above)" in md
    assert "commit `0123456789ab`" in md and "2026-10-19 12:00 UTC" in md
    assert "| gitleaks | 1 | 0 | 0 | 0 | 0 | 1 |" in md and "| **Total** | **1** | **2** | **1** | **1** | **0** | **5** |" in md
    assert "shell=True \\| pipe" in md                                   # pipes escaped
    assert "[`app.py:47`](https://github.com/o/r/blob/0123456789abcdef/app.py#L47)" in md
    assert "[PYSEC-1](https://osv.dev/vulnerability/PYSEC-1)" in md and "(CWE-798)" in md
    assert "## Secrets · gitleaks (1)" in md and "## Vulnerable dependencies · pip-audit (1)" in md


def test_markdown_pass_none_and_truncation():
    md = to_markdown([], fail_on="high", generated=WHEN)
    assert "**0 findings**" in md and "**PASS**" in md and md.count("No findings.") == 4
    assert "Gate: disabled" in to_markdown([], fail_on="none", generated=WHEN)
    many = [Finding("bandit", f"B{i}", "low", "t", "a.py", i) for i in range(1, 60)]
    md = to_markdown(many, max_rows=50, tools_run=("bandit",), generated=WHEN)
    assert "9 more in the JSON and SARIF files" in md and "## Secrets" not in md


def test_sarif():
    doc = to_sarif(dedupe(sample()))
    assert doc["version"] == "2.1.0" and [r["tool"]["driver"]["name"] for r in doc["runs"]] == [
        "SecureFlow gitleaks", "SecureFlow bandit", "SecureFlow semgrep", "SecureFlow pip-audit"]
    bandit = doc["runs"][1]
    assert len(bandit["results"]) == 2 and len(bandit["tool"]["driver"]["rules"]) == 2
    res = bandit["results"][0]
    assert res["ruleId"] == "B602" and res["level"] == "error" and res["ruleIndex"] == 0
    assert res["locations"][0]["physicalLocation"] == {"artifactLocation": {"uri": "app.py", "uriBaseId": "%SRCROOT%"},
                                                       "region": {"startLine": 47}}
    assert res["partialFingerprints"]["secureflow/v1"] and "Remediation: use a list" in res["message"]["text"]
    rule = bandit["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "8.0" and "security" in rule["properties"]["tags"]
    gl = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert gl["properties"]["security-severity"] == "9.5" and "CWE-798" in gl["properties"]["tags"] and "helpUri" not in gl
    pa = doc["runs"][3]["tool"]["driver"]["rules"][0]
    assert pa["helpUri"] == "https://osv.dev/vulnerability/PYSEC-1"


def test_sarif_omits_region_for_unknown_line():
    doc = to_sarif([Finding("pip-audit", "P", "high", "t", "requirements.txt", 0)], tools_run=("pip-audit",))
    assert "region" not in doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert len(doc["runs"]) == 1


def test_json_round_trip():
    out = dedupe(sample())
    text = to_json(out, fail_on="high", commit="abc", paths=".", generated=WHEN)
    doc = json.loads(text)
    assert doc["counts"]["critical"] == 1 and doc["gate_breaches"] == 3 and doc["by_tool"]["bandit"] == 2
    back, meta = from_json(text)
    assert back == out and meta["commit"] == "abc"
