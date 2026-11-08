"""Turn findings into a Markdown report, a SARIF 2.1.0 file, a JSON file and a gate decision."""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from datetime import UTC, datetime
from urllib.parse import quote

from . import REPO_URL, __version__
from .findings import LEVELS, SCORES, SEVERITIES, TOOLS, Finding, at_or_above

SECTION = {"gitleaks": "Secrets", "bandit": "Python static analysis", "semgrep": "Static analysis",
           "pip-audit": "Vulnerable dependencies"}


def dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per fingerprint, ordered by severity, tool, file and line."""
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.fingerprint, f)
    return sorted(seen.values(), key=lambda f: (f.rank, TOOLS.index(f.tool), f.file, f.line, f.rule_id))


def counts(findings: list[Finding]) -> dict[str, int]:
    return {s: sum(f.severity == s for f in findings) for s in SEVERITIES}


def gate(findings: list[Finding], fail_on: str) -> list[Finding]:
    """The findings that breach the threshold; empty means the gate passes."""
    return [f for f in findings if at_or_above(f.severity, fail_on)]


_MD_SPECIAL = re.compile(r"([\\`\[\]<>|])")
_URL_SAFE = ":/?#&=%+~@!$,;*'"  # everything else, spaces and parentheses included, is percent-encoded


def _cell(text: str) -> str:
    """Finding text (it can quote the scanned code) as plain text: no HTML, links, code spans or notifications."""
    text = _MD_SPECIAL.sub(r"\\\1", str(text).replace("\n", " ").strip())
    return text.replace("@", "@\u200b").replace("#", "#\u200b")  # zero-width space: no @mentions or #references


def _code(text: str) -> str:
    """Inline code in a table cell; a backtick in the text needs a longer fence."""
    text = str(text).replace("|", "\\|").replace("\n", " ").strip()
    return f"`` {text} ``" if "`" in text else f"`{text}`"


def _location(f: Finding, repo: str, commit: str) -> str:
    loc = f"{f.file}:{f.line}" if f.line else f.file
    if repo and commit and f.file:
        anchor = f"#L{f.line}" if f.line else ""
        return f"[{_code(loc)}]({repo}/blob/{commit}/{quote(f.file)}{anchor})"
    return _code(loc)


def to_markdown(findings: list[Finding], *, title: str = "SecureFlow security report", fail_on: str = "high",
                commit: str = "", paths: str = "", repo: str = "", tools_run: tuple[str, ...] = TOOLS,
                max_rows: int = 50, generated: datetime | None = None, scan_errors: dict | None = None) -> str:
    generated = generated or datetime.now(UTC)
    c = counts(findings)
    breaches = gate(findings, fail_on)
    lines = [f"# {title}", ""]
    summary = " · ".join(f"{c[s]} {s}" for s in SEVERITIES)
    lines.append(f"**{len(findings)} finding{'s' if len(findings) != 1 else ''}** · {summary}  ")
    if fail_on == "none":
        lines.append("Gate: disabled (`fail-on: none`)  ")
    elif breaches:
        lines.append(f"Gate `{fail_on}`: **FAIL** ({len(breaches)} at {fail_on} or above)  ")
    else:
        lines.append(f"Gate `{fail_on}`: **PASS**  ")
    if any((scan_errors or {}).values()):
        errs = ", ".join(f"{t} {n}" for t, n in scan_errors.items() if n)
        lines.append(f"**Not fully scanned:** scanner errors ({errs}); a file a scanner could not read was not "
                     "checked. See the scanner's step log.  ")
    meta = [f"commit `{commit[:12]}`" if commit else "", f"scanned `{paths}`" if paths else "",
            f"{generated:%Y-%m-%d %H:%M} UTC", f"tools: {', '.join(tools_run)}"]
    lines += [" · ".join(m for m in meta if m), ""]

    lines += ["| Tool | " + " | ".join(s.title() for s in SEVERITIES) + " | Total |",
              "|---|" + "---|" * (len(SEVERITIES) + 1)]
    for tool in tools_run:
        tc = counts([f for f in findings if f.tool == tool])
        lines.append(f"| {tool} | " + " | ".join(str(tc[s]) for s in SEVERITIES) + f" | {sum(tc.values())} |")
    lines.append("| **Total** | " + " | ".join(f"**{c[s]}**" for s in SEVERITIES) + f" | **{len(findings)}** |")
    lines.append("")

    for tool in tools_run:
        fs = [f for f in findings if f.tool == tool]
        lines.append(f"## {SECTION[tool]} · {tool} ({len(fs)})")
        lines.append("")
        if not fs:
            lines += ["No findings.", ""]
            continue
        lines += ["| Severity | Rule | Location | Finding | Remediation |", "|---|---|---|---|---|"]
        for f in fs[:max_rows]:
            rule = f"[{_cell(f.rule_id)}]({quote(f.url, safe=_URL_SAFE)})" if f.url else _cell(f.rule_id)
            cwe = f" ({_cell(f.cwe)})" if f.cwe else ""
            lines.append(f"| {f.severity} | {rule} | {_location(f, repo, commit)} | {_cell(f.title)}{cwe} | "
                         f"{_cell(f.remediation)} |")
        if len(fs) > max_rows:
            lines.append(f"| … | | | {len(fs) - max_rows} more in the JSON and SARIF files | |")
        lines.append("")
    lines.append(f"<sub>Generated by [SecureFlow]({REPO_URL}) {__version__}. Secrets are redacted; "
                 "rotate anything Gitleaks reports before doing anything else.</sub>")
    return "\n".join(lines) + "\n"


def to_sarif(findings: list[Finding], tools_run: tuple[str, ...] = TOOLS) -> dict:
    runs = []
    for tool in tools_run:
        rules: dict[str, dict] = {}
        results = []
        for f in (x for x in findings if x.tool == tool):
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id, "name": f.rule_id,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description or f.title},
                    "help": {"text": f.remediation or f.description or f.title},
                    "properties": {"security-severity": SCORES[f.severity],
                                   "tags": ["security"] + ([f.cwe] if f.cwe else [])},
                }
                if f.url:
                    rules[f.rule_id]["helpUri"] = f.url
            location = {"physicalLocation": {"artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"}}}
            if f.line:
                location["physicalLocation"]["region"] = {"startLine": f.line}
            text = f.title + (f" Remediation: {f.remediation}" if f.remediation else "")
            # No partialFingerprints: upload-sarif computes primaryLocationLineHash from the line's content,
            # which survives lines added above; our fingerprint includes the line number and would not.
            results.append({
                "ruleId": f.rule_id, "ruleIndex": list(rules).index(f.rule_id), "level": LEVELS[f.severity],
                "message": {"text": text}, "locations": [location],
            })
        runs.append({
            "tool": {"driver": {"name": f"SecureFlow {tool}", "version": __version__,
                                "informationUri": REPO_URL, "rules": list(rules.values())}},
            "results": results,
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": runs}


def to_json(findings: list[Finding], *, fail_on: str = "high", commit: str = "", paths: str = "",
            tools_run: tuple[str, ...] = TOOLS, generated: datetime | None = None,
            scan_errors: dict | None = None) -> str:
    generated = generated or datetime.now(UTC)
    doc = {
        "tool": "secureflow", "version": __version__, "generated": generated.isoformat(timespec="seconds"),
        "commit": commit, "paths": paths, "fail_on": fail_on, "tools_run": list(tools_run),
        "counts": counts(findings),
        "by_tool": {t: len([f for f in findings if f.tool == t]) for t in tools_run},
        "gate_breaches": len(gate(findings, fail_on)),
        "scan_errors": scan_errors or {},
        "findings": [asdict(f) for f in findings],
    }
    return json.dumps(doc, indent=2)


def from_json(text: str) -> tuple[list[Finding], dict]:
    doc = json.loads(text)
    return [Finding(**f) for f in doc.get("findings", [])], doc
