from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any

VALID_SEVERITIES = {"low", "medium", "high"}


@dataclass(slots=True)
class Rule:
    id: str
    title: str
    severity: str
    description: str
    patterns: list[str]
    languages: list[str]
    remediation: str
    cwe: str | None = None
    references: list[str] = field(default_factory=list)
    any_of: list[str] = field(default_factory=list)
    all_of: list[str] = field(default_factory=list)
    _compiled_patterns: list[re.Pattern[str]] = field(init=False, repr=False)
    _compiled_any_of: list[re.Pattern[str]] = field(init=False, repr=False)
    _compiled_all_of: list[re.Pattern[str]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{self.severity}' for rule {self.id}")
        if not self.patterns:
            raise ValueError(f"Rule {self.id} must define at least one primary pattern")
        self._compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.patterns]
        self._compiled_any_of = [re.compile(pattern, re.IGNORECASE) for pattern in self.any_of]
        self._compiled_all_of = [re.compile(pattern, re.IGNORECASE) for pattern in self.all_of]

    def primary_match(self, text: str) -> re.Match[str] | None:
        for pattern in self._compiled_patterns:
            match = pattern.search(text)
            if match:
                return match
        return None

    def matches_window(self, line_text: str, window_text: str) -> re.Match[str] | None:
        match = self.primary_match(line_text)
        if not match:
            return None
        if self._compiled_any_of and not any(regex.search(window_text) for regex in self._compiled_any_of):
            return None
        if self._compiled_all_of and not all(regex.search(window_text) for regex in self._compiled_all_of):
            return None
        return match


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    match_text: str
    snippet: str
    remediation: str
    description: str
    cwe: str | None = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "match_text": self.match_text,
            "snippet": self.snippet,
            "remediation": self.remediation,
            "description": self.description,
            "cwe": self.cwe,
            "references": self.references,
        }


@dataclass(slots=True)
class ScanReport:
    root: str
    findings: list[Finding]
    scanned_files: int

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def has_findings_at_or_above(self, threshold: str) -> bool:
        order = {"low": 1, "medium": 2, "high": 3}
        floor = order[threshold]
        return any(order[finding.severity] >= floor for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "scanned_files": self.scanned_files,
            "total_findings": len(self.findings),
            "severity_counts": self.severity_counts,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(slots=True)
class ScanTarget:
    path: Path
    language: str
