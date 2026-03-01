from __future__ import annotations

from pathlib import Path
from typing import Iterable

from legacysec.models import Finding, Rule, ScanReport
from legacysec.utils import discover_targets, format_snippet, is_cobol_comment


def scan_path(path: Path, rules: Iterable[Rule]) -> ScanReport:
    targets = discover_targets(path)
    rules_by_language: dict[str, list[Rule]] = {}
    for rule in rules:
        for language in rule.languages:
            rules_by_language.setdefault(language.lower(), []).append(rule)

    findings: list[Finding] = []
    for target in targets:
        findings.extend(_scan_file(target.path, target.language, rules_by_language.get(target.language, [])))

    return ScanReport(root=str(path), findings=findings, scanned_files=len(targets))


def _scan_file(path: Path, language: str, rules: list[Rule]) -> list[Finding]:
    if language != "cobol" or not rules:
        return []

    lines = path.read_text(encoding="utf-8").splitlines()
    findings: list[Finding] = []
    for index, line in enumerate(lines):
        if is_cobol_comment(line):
            continue
        window = _window_text(lines, index)
        for rule in rules:
            match = rule.matches_window(line, window)
            if not match:
                continue
            findings.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    file=str(path),
                    line=index + 1,
                    match_text=match.group(0),
                    snippet=format_snippet(lines, index),
                    remediation=rule.remediation,
                    description=rule.description,
                    cwe=rule.cwe,
                    references=rule.references,
                )
            )
    return findings


def _window_text(lines: list[str], index: int) -> str:
    start = max(0, index - 1)
    end = min(len(lines), index + 2)
    return "\n".join(lines[start:end])
