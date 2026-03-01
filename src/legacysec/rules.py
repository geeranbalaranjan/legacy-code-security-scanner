from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    yaml = None

from legacysec.models import Rule


def default_ruleset_path(language: str = "cobol") -> Path:
    return Path(__file__).resolve().parent / "rulesets" / f"{language}.yml"


def load_ruleset(path: Path | None = None) -> list[Rule]:
    ruleset_path = path or default_ruleset_path()
    if not ruleset_path.exists():
        raise FileNotFoundError(f"Ruleset file not found: {ruleset_path}")

    try:
        raw_data = _load_rules_document(ruleset_path)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Ruleset file is not valid YAML/JSON: {ruleset_path}. "
            "Install PyYAML for full YAML support."
        ) from exc
    except Exception as exc:
        if yaml is not None and isinstance(exc, yaml.YAMLError):
            raise ValueError(f"Ruleset file is not valid YAML: {ruleset_path}") from exc
        raise

    if not isinstance(raw_data, dict) or not isinstance(raw_data.get("rules"), list):
        raise ValueError(f"Ruleset file must contain a top-level 'rules' list: {ruleset_path}")

    rules: list[Rule] = []
    for index, item in enumerate(raw_data["rules"], start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Rule #{index} in {ruleset_path} must be a mapping")
        rules.append(_build_rule(item, ruleset_path, index))
    return rules


def _build_rule(item: dict[str, Any], ruleset_path: Path, index: int) -> Rule:
    required = ["id", "title", "severity", "description", "patterns", "languages", "remediation"]
    missing = [field for field in required if field not in item]
    if missing:
        fields = ", ".join(missing)
        raise ValueError(f"Rule #{index} in {ruleset_path} is missing required fields: {fields}")

    try:
        return Rule(
            id=str(item["id"]),
            title=str(item["title"]),
            severity=str(item["severity"]).lower(),
            description=str(item["description"]),
            patterns=_as_string_list(item["patterns"], "patterns", ruleset_path, index),
            languages=_as_string_list(item["languages"], "languages", ruleset_path, index),
            remediation=str(item["remediation"]),
            cwe=str(item["cwe"]) if item.get("cwe") is not None else None,
            references=_as_string_list(item.get("references", []), "references", ruleset_path, index),
            any_of=_as_string_list(item.get("any_of", []), "any_of", ruleset_path, index),
            all_of=_as_string_list(item.get("all_of", []), "all_of", ruleset_path, index),
        )
    except re.error as exc:
        raise ValueError(f"Invalid regex in rule #{index} in {ruleset_path}: {exc}") from exc
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Invalid rule #{index} in {ruleset_path}: {exc}") from exc


def _as_string_list(value: Any, field_name: str, ruleset_path: Path, index: int) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(
            f"Rule #{index} in {ruleset_path} must define '{field_name}' as a list of strings"
        )
    return list(value)


def _load_rules_document(ruleset_path: Path) -> Any:
    content = ruleset_path.read_text(encoding="utf-8")
    if yaml is not None:
        return yaml.safe_load(content)
    return json.loads(content)
