from pathlib import Path

from legacysec.report import render_html, render_json
from legacysec.rules import load_ruleset
from legacysec.scanner import scan_path


def test_scan_samples_produces_expected_findings() -> None:
    report = scan_path(Path("samples/cobol"), load_ruleset())

    assert report.scanned_files == 2
    assert len(report.findings) == 6
    assert report.severity_counts == {"high": 4, "medium": 2, "low": 0}

    findings_by_rule = {}
    for finding in report.findings:
        findings_by_rule[finding.rule_id] = findings_by_rule.get(finding.rule_id, 0) + 1

    assert findings_by_rule == {
        "COBOL-001": 2,
        "COBOL-002": 1,
        "COBOL-003": 1,
        "COBOL-004": 1,
        "COBOL-005": 1,
    }


def test_report_renderers_include_summary_details() -> None:
    report = scan_path(Path("samples/cobol"), load_ruleset())

    json_output = render_json(report)
    html_output = render_html(report)

    assert '"total_findings": 6' in json_output
    assert "legacysec Scan Report" in html_output
    assert "High (4)" in html_output
    assert "samples\\cobol\\insecure.cbl" in html_output or "samples/cobol/insecure.cbl" in html_output
