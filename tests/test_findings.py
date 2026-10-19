import pytest

from secureflow.findings import Finding, at_or_above


def test_normalises_path_and_line_and_fingerprint():
    f = Finding("bandit", "B101", "low", "t", "./././samples\\app.py", "12")
    assert f.file == "samples/app.py" and f.line == 12
    assert f.fingerprint == Finding("bandit", "B101", "low", "other title", "samples/app.py", 12).fingerprint
    assert f.fingerprint != Finding("bandit", "B101", "low", "t", "samples/app.py", 13).fingerprint
    assert Finding("bandit", "B101", "low", "t", ".github/x.yml", 0).file == ".github/x.yml"


def test_explicit_fingerprint_is_kept():
    assert Finding("gitleaks", "r", "critical", "t", "f", 1, fingerprint="abc").fingerprint == "abc"


@pytest.mark.parametrize("bad", [dict(tool="nmap"), dict(severity="urgent")])
def test_rejects_unknown_tool_or_severity(bad):
    kw = dict(tool="bandit", rule_id="B1", severity="low", title="t", file="f", line=1) | bad
    with pytest.raises(ValueError):
        Finding(**kw)


def test_at_or_above():
    assert at_or_above("critical", "high") and at_or_above("high", "high")
    assert not at_or_above("medium", "high") and not at_or_above("critical", "none")
    with pytest.raises(ValueError):
        at_or_above("high", "severe")
