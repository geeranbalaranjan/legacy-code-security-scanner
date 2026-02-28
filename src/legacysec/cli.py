from __future__ import annotations

import argparse
from pathlib import Path
import sys

from legacysec.report import write_reports
from legacysec.rules import load_ruleset
from legacysec.scanner import scan_path
from legacysec.utils import coerce_output_formats, normalize_fail_on


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="legacysec", description="Scan legacy code for insecure patterns.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a file or directory.")
    scan_parser.add_argument("path", help="File or directory to scan.")
    scan_parser.add_argument(
        "--format",
        default="json",
        help="Comma-separated output formats. Supported: json, html.",
    )
    scan_parser.add_argument("--out", default="out", help="Output directory for generated reports.")
    scan_parser.add_argument(
        "--fail-on",
        default=None,
        help="Exit with code 2 if any finding meets or exceeds this severity: low, medium, high.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.error(f"Unsupported command: {args.command}")

    try:
        formats = coerce_output_formats(args.format)
        fail_on = normalize_fail_on(args.fail_on)
        rules = load_ruleset()
        report = scan_path(Path(args.path), rules)
        written = write_reports(report, Path(args.out), formats)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(
        f"Scanned {report.scanned_files} file(s), found {len(report.findings)} issue(s). "
        f"Reports: {', '.join(str(path) for path in written)}"
    )

    if fail_on and report.has_findings_at_or_above(fail_on):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
