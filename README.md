# legacysec

`legacysec` is an offline-first MVP security scanner for legacy codebases, starting with COBOL. It uses a simple rule-driven engine plus line-oriented parsing to detect common risky patterns and generate JSON and HTML reports.

## Features

- Rule-based scanning from `src/legacysec/rulesets/<language>.yml`
- COBOL-aware line scanning with comment filtering
- JSON and HTML reports with severity, file, line, snippet, and remediation
- CI-friendly exit codes via `--fail-on`

## Install

```bash
python -m pip install -e .
```

## Usage

Scan the bundled sample COBOL code and write both report formats:

```bash
legacysec scan samples/cobol --format json,html --out out
```

Fail CI if any `high` severity findings are present:

```bash
legacysec scan samples/cobol --format json --out out --fail-on high
```

Run without installation from the repository root:

```bash
$env:PYTHONPATH="src"
python -m legacysec.cli scan samples/cobol --format json,html --out out
```

## Reports

- `report.json`: machine-readable findings and summary metadata
- `report.html`: grouped by severity with file/line details and snippets

## Rules

Rules live in `src/legacysec/rulesets/` and are easy to extend. Each rule supports:

- `id`
- `title`
- `severity`: `low`, `medium`, or `high`
- `description`
- `cwe` (optional)
- `patterns`: primary regex list
- `languages`
- `remediation`
- `references` (optional)
- `any_of` (optional): at least one regex must match the surrounding scan window
- `all_of` (optional): all regexes must match the surrounding scan window

Example shape:

```yaml
rules:
  - id: EXAMPLE-001
    title: Example heuristic
    severity: medium
    description: Detects a suspicious construct.
    patterns:
      - "SOME\\s+PATTERN"
    any_of:
      - "ARG1"
      - "ARG2"
    languages: ["cobol"]
    remediation: Replace with validated input and explicit allowlists.
```

## Testing

```bash
pytest
```
