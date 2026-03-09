from pathlib import Path

import pytest

from legacysec.rules import default_ruleset_path, load_ruleset


def test_load_default_ruleset() -> None:
    rules = load_ruleset()
    assert len(rules) == 5
    assert {rule.id for rule in rules} == {
        "COBOL-001",
        "COBOL-002",
        "COBOL-003",
        "COBOL-004",
        "COBOL-005",
    }


def test_missing_ruleset_raises_helpful_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing.yml"
    with pytest.raises(FileNotFoundError, match="Ruleset file not found"):
        load_ruleset(missing)


def test_invalid_ruleset_schema_raises(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.yml"
    invalid.write_text("rules: [123]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a mapping"):
        load_ruleset(invalid)


def test_default_ruleset_path_points_to_packaged_file() -> None:
    assert default_ruleset_path().name == "cobol.yml"
