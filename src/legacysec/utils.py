from __future__ import annotations

from pathlib import Path

from legacysec.models import ScanTarget, VALID_SEVERITIES

COBOL_EXTENSIONS = {".cbl", ".cob", ".cobol", ".cpy"}
OUTPUT_FORMATS = {"json", "html"}


def coerce_output_formats(raw_value: str) -> list[str]:
    formats = [item.strip().lower() for item in raw_value.split(",") if item.strip()]
    if not formats:
        raise ValueError("At least one output format must be provided")
    invalid = sorted({item for item in formats if item not in OUTPUT_FORMATS})
    if invalid:
        allowed = ", ".join(sorted(OUTPUT_FORMATS))
        raise ValueError(f"Unsupported output format(s): {', '.join(invalid)}. Allowed: {allowed}")
    return list(dict.fromkeys(formats))


def normalize_fail_on(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized not in VALID_SEVERITIES:
        allowed = ", ".join(sorted(VALID_SEVERITIES))
        raise ValueError(f"Invalid --fail-on severity '{value}'. Allowed: {allowed}")
    return normalized


def discover_targets(root: Path) -> list[ScanTarget]:
    if not root.exists():
        raise FileNotFoundError(f"Scan path does not exist: {root}")
    if root.is_file():
        target = _target_from_file(root)
        return [target] if target else []
    targets: list[ScanTarget] = []
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        target = _target_from_file(path)
        if target:
            targets.append(target)
    return targets


def format_snippet(lines: list[str], index: int) -> str:
    start = max(0, index - 1)
    end = min(len(lines), index + 2)
    snippet_lines = []
    for line_number in range(start, end):
        snippet_lines.append(f"{line_number + 1}: {lines[line_number].rstrip()}")
    return "\n".join(snippet_lines)


def is_cobol_comment(line: str) -> bool:
    stripped = line.lstrip()
    if stripped.startswith("*>"):
        return True
    return len(line) >= 7 and line[6] == "*"


def _target_from_file(path: Path) -> ScanTarget | None:
    if path.suffix.lower() in COBOL_EXTENSIONS:
        return ScanTarget(path=path, language="cobol")
    return None
