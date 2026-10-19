"""The normalised finding every scanner is mapped to."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

SEVERITIES = ("critical", "high", "medium", "low", "info")
TOOLS = ("gitleaks", "bandit", "semgrep", "pip-audit")
# SARIF levels and GitHub code-scanning "security-severity" scores per severity.
LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SCORES = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}

_DOT_SLASH = re.compile(r"^(\./)+")


@dataclass
class Finding:
    tool: str
    rule_id: str
    severity: str
    title: str
    file: str
    line: int
    description: str = ""
    remediation: str = ""
    url: str = ""
    cwe: str = ""
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if self.tool not in TOOLS:
            raise ValueError(f"unknown tool {self.tool!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")
        self.file = _DOT_SLASH.sub("", self.file.replace("\\", "/"))
        self.line = max(int(self.line or 0), 0)
        if not self.fingerprint:
            key = f"{self.tool}|{self.rule_id}|{self.file}|{self.line}"
            self.fingerprint = hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def rank(self) -> int:
        return SEVERITIES.index(self.severity)


def at_or_above(severity: str, threshold: str) -> bool:
    """True when `severity` is at least as serious as `threshold`. `none` never matches."""
    if threshold == "none":
        return False
    if threshold not in SEVERITIES:
        raise ValueError(f"threshold must be none or one of {', '.join(SEVERITIES)}")
    return SEVERITIES.index(severity) <= SEVERITIES.index(threshold)
