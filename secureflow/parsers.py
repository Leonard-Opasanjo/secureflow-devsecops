"""Readers for each scanner's JSON output. A missing or empty file means the scanner found nothing."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .findings import SEVERITIES, Finding

_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def load_json(path: str | Path):
    """Return the parsed file, or None when it is absent or empty. Invalid JSON raises ValueError."""
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"{p}: not valid JSON ({e})") from e


def _first_line(text: str, limit: int = 160) -> str:
    line = (text or "").strip().splitlines()[0] if (text or "").strip() else ""
    return line if len(line) <= limit else line[: limit - 1] + "…"


def parse_bandit(data) -> list[Finding]:
    sev = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    out = []
    for r in (data or {}).get("results", []):
        cwe = (r.get("issue_cwe") or {}).get("id")
        out.append(Finding(
            "bandit", r["test_id"], sev.get(r.get("issue_severity", ""), "low"), _first_line(r["issue_text"]),
            r["filename"], r.get("line_number", 0),
            description=f"{r.get('test_name', '')} (confidence {r.get('issue_confidence', '?').lower()})",
            url=r.get("more_info", ""), cwe=f"CWE-{cwe}" if cwe else ""))
    return out


def parse_semgrep(data) -> list[Finding]:
    sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    out = []
    for r in (data or {}).get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        severity = sev.get(str(extra.get("severity", "")).upper(), "low")
        if meta.get("impact") == "HIGH" and SEVERITIES.index(severity) > SEVERITIES.index("high"):
            severity = "high"  # Semgrep marks many WARNING rules as high impact; treat those as high
        cwe = meta.get("cwe") or ""
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else ""
        cwe = str(cwe).split(":")[0].strip()
        out.append(Finding(
            "semgrep", r["check_id"], severity, _first_line(extra.get("message") or r["check_id"]),
            r["path"], r.get("start", {}).get("line", 0),
            description=(extra.get("message") or "").strip(),
            remediation=(extra.get("fix") or "").strip(),
            url=meta.get("source") or meta.get("shortlink") or "", cwe=cwe))
    return out


def parse_gitleaks(data) -> list[Finding]:
    out = []
    for leak in data or []:
        commit = (leak.get("Commit") or "")[:7]
        when = (leak.get("Date") or "")[:10]
        where = f"commit {commit} on {when}" if commit else "working tree"
        out.append(Finding(
            "gitleaks", leak["RuleID"], "critical", leak.get("Description") or leak["RuleID"],
            leak["File"], leak.get("StartLine", 0),
            description=f"Found in {where}. Match: {leak.get('Match', '')}",
            remediation="Revoke and rotate the credential now; then remove it from history (git filter-repo) "
                        "and load it from a secret store or environment variable.",
            cwe="CWE-798"))
    return out


def _locate(package: str, requirements: list[Path]) -> tuple[str, int]:
    """Find the requirements line that pins `package`, so the finding points at it."""
    norm = package.lower().replace("_", "-")
    for req in requirements:
        try:
            lines = Path(req).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            m = _REQ_NAME.match(line)
            if m and m.group(1).lower().replace("_", "-") == norm:
                return str(req), n
    return (str(requirements[0]) if requirements else "requirements.txt"), 0


def parse_pip_audit(data, requirements: list[Path] | None = None) -> list[Finding]:
    out = []
    for dep in (data or {}).get("dependencies", []):
        for v in dep.get("vulns", []):
            file, line = _locate(dep["name"], requirements or [])
            fixes = ", ".join(v.get("fix_versions") or []) or "no fixed version published"
            aliases = ", ".join(a for a in v.get("aliases", []) if a.startswith("CVE-"))
            out.append(Finding(
                "pip-audit", v["id"], "high", f"{dep['name']} {dep['version']} is affected by {v['id']}",
                file, line,
                description=(f"{aliases}. " if aliases else "") + _first_line(v.get("description", ""), 300),
                remediation=f"Upgrade {dep['name']} to {fixes}",
                url=f"https://osv.dev/vulnerability/{v['id']}", cwe="CWE-1395"))
    return out
