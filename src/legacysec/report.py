from __future__ import annotations

from collections import defaultdict
from datetime import datetime, UTC
from html import escape
import json
from pathlib import Path

from legacysec.models import ScanReport

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def write_reports(report: ScanReport, output_dir: Path, formats: list[str]) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if "json" in formats:
        json_path = output_dir / "report.json"
        json_path.write_text(render_json(report), encoding="utf-8")
        written.append(json_path)
    if "html" in formats:
        html_path = output_dir / "report.html"
        html_path.write_text(render_html(report), encoding="utf-8")
        written.append(html_path)
    return written


def render_json(report: ScanReport) -> str:
    payload = report.to_dict()
    payload["generated_at"] = datetime.now(UTC).isoformat()
    return json.dumps(payload, indent=2)


def render_html(report: ScanReport) -> str:
    grouped: dict[str, list] = defaultdict(list)
    for finding in report.findings:
        grouped[finding.severity].append(finding)

    sections: list[str] = []
    for severity in sorted(grouped, key=lambda item: SEVERITY_ORDER[item]):
        cards: list[str] = []
        for index, finding in enumerate(grouped[severity], start=1):
            anchor = f"{severity}-{index}"
            references = ""
            if finding.references:
                links = "".join(
                    f'<li><a href="{escape(ref)}">{escape(ref)}</a></li>' for ref in finding.references
                )
                references = f"<p><strong>References</strong></p><ul>{links}</ul>"
            cwe = f"<p><strong>CWE:</strong> {escape(finding.cwe)}</p>" if finding.cwe else ""
            cards.append(
                "<article class='finding'>"
                f"<a id='{anchor}'></a>"
                f"<h3>{escape(finding.rule_id)}: {escape(finding.title)}</h3>"
                f"<p><strong>Location:</strong> {escape(finding.file)}:{finding.line}</p>"
                f"<p><strong>Match:</strong> <code>{escape(finding.match_text)}</code></p>"
                f"<p>{escape(finding.description)}</p>"
                f"{cwe}"
                f"<p><strong>Remediation:</strong> {escape(finding.remediation)}</p>"
                f"<pre>{escape(finding.snippet)}</pre>"
                f"{references}"
                "</article>"
            )
        sections.append(
            "<section>"
            f"<h2>{escape(severity.title())} ({len(grouped[severity])})</h2>"
            + "".join(cards)
            + "</section>"
        )

    return (
        "<!DOCTYPE html>"
        "<html lang='en'>"
        "<head>"
        "<meta charset='utf-8'>"
        "<title>legacysec report</title>"
        "<style>"
        "body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;background:#f7f7f5;color:#1f2933;}"
        "h1,h2,h3{color:#102a43;}"
        ".summary{padding:1rem;background:#fff;border:1px solid #d9e2ec;border-radius:8px;margin-bottom:1.5rem;}"
        ".finding{padding:1rem;background:#fff;border:1px solid #d9e2ec;border-radius:8px;margin:1rem 0;}"
        "pre{white-space:pre-wrap;background:#f0f4f8;padding:0.75rem;border-radius:6px;}"
        "code{background:#f0f4f8;padding:0.1rem 0.25rem;border-radius:4px;}"
        "a{color:#0b6e4f;}"
        "</style>"
        "</head>"
        "<body>"
        "<h1>legacysec Scan Report</h1>"
        f"<div class='summary'><p><strong>Root:</strong> {escape(report.root)}</p>"
        f"<p><strong>Scanned files:</strong> {report.scanned_files}</p>"
        f"<p><strong>Total findings:</strong> {len(report.findings)}</p>"
        f"<p><strong>Severity counts:</strong> high={report.severity_counts['high']}, "
        f"medium={report.severity_counts['medium']}, low={report.severity_counts['low']}</p></div>"
        + "".join(sections)
        + "</body></html>"
    )
