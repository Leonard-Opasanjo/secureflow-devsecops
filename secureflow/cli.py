"""Command-line interface: `secureflow report` builds the outputs, `secureflow gate` decides pass or fail."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .findings import SEVERITIES, at_or_above
from .parsers import load_json, parse_bandit, parse_gitleaks, parse_pip_audit, parse_semgrep
from .report import counts, dedupe, from_json, gate, to_json, to_markdown, to_sarif

THRESHOLDS = ("none", *SEVERITIES)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secureflow", description="Merge security scanner output into one report")
    p.add_argument("--version", action="version", version=f"secureflow {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("report", help="read scanner JSON files and write Markdown, SARIF and JSON")
    r.add_argument("--bandit", metavar="JSON", help="bandit -f json output")
    r.add_argument("--semgrep", metavar="JSON", help="semgrep --json output")
    r.add_argument("--gitleaks", metavar="JSON", action="append", default=[],
                   help="gitleaks --report-format json output (repeatable)")
    r.add_argument("--pip-audit", metavar="JSON[:REQUIREMENTS]", action="append", default=[],
                   help="pip-audit -f json output, optionally with the requirements file it audited (repeatable)")
    r.add_argument("--markdown", metavar="FILE", help="write the Markdown report here")
    r.add_argument("--sarif", metavar="FILE", help="write SARIF 2.1.0 here (for GitHub code scanning)")
    r.add_argument("--json", metavar="FILE", help="write the findings JSON here (input for `gate`)")
    r.add_argument("--title", default="SecureFlow security report")
    r.add_argument("--fail-on", default="high", choices=THRESHOLDS, help="threshold shown in the report")
    r.add_argument("--commit", default="", help="commit SHA, used for links and the report header")
    r.add_argument("--repo", default="", help="repository URL, used to link locations to source lines")
    r.add_argument("--paths", default="", help="what was scanned, for the report header")
    r.add_argument("--max-rows", type=int, default=50, help="rows per tool in the Markdown table")

    g = sub.add_parser("gate", help="exit 1 when the findings JSON has anything at or above the threshold")
    g.add_argument("findings", metavar="FINDINGS.json")
    g.add_argument("--fail-on", default="high", choices=THRESHOLDS)
    return p


def _collect(args: argparse.Namespace):
    findings, tools_run = [], []
    if args.bandit is not None:
        tools_run.append("bandit")
        findings += parse_bandit(load_json(args.bandit))
    if args.semgrep is not None:
        tools_run.append("semgrep")
        findings += parse_semgrep(load_json(args.semgrep))
    if args.gitleaks:
        tools_run.append("gitleaks")
        for path in args.gitleaks:
            findings += parse_gitleaks(load_json(path))
    if args.pip_audit:
        tools_run.append("pip-audit")
        for spec in args.pip_audit:
            path, _, req = spec.partition(":")
            findings += parse_pip_audit(load_json(path), [Path(req)] if req else [])
    order = ("gitleaks", "bandit", "semgrep", "pip-audit")
    return dedupe(findings), tuple(t for t in order if t in tools_run)


def report(args: argparse.Namespace) -> int:
    findings, tools_run = _collect(args)
    if not tools_run:
        raise ValueError("give at least one scanner output (--bandit, --semgrep, --gitleaks, --pip-audit)")
    common = dict(fail_on=args.fail_on, commit=args.commit, paths=args.paths, tools_run=tools_run)
    if args.markdown:
        Path(args.markdown).write_text(to_markdown(findings, title=args.title, repo=args.repo,
                                                   max_rows=args.max_rows, **common), encoding="utf-8")
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(findings, tools_run), indent=2),
                                    encoding="utf-8")
    if args.json:
        Path(args.json).write_text(to_json(findings, **common), encoding="utf-8")
    c = counts(findings)
    print(f"{len(findings)} findings: " + ", ".join(f"{c[s]} {s}" for s in SEVERITIES)
          + f" (tools: {', '.join(tools_run)})")
    breaches = gate(findings, args.fail_on)
    print(f"gate {args.fail_on}: " + (f"FAIL, {len(breaches)} at or above" if breaches else "PASS"))
    return 0


def run_gate(args: argparse.Namespace) -> int:
    findings, _ = from_json(Path(args.findings).read_text(encoding="utf-8"))
    breaches = [f for f in findings if at_or_above(f.severity, args.fail_on)]
    if not breaches:
        print(f"gate {args.fail_on}: PASS ({len(findings)} findings, none at or above {args.fail_on})")
        return 0
    print(f"gate {args.fail_on}: FAIL, {len(breaches)} finding(s) at or above {args.fail_on}:")
    for f in breaches:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        print(f"  {f.severity:<8} {f.tool:<9} {f.rule_id:<40} {loc}")
    return 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return run_gate(args) if args.command == "gate" else report(args)
    except (OSError, ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
