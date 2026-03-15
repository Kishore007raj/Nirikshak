"""Rule loader for Nirikshak.

Rules are defined as YAML files under the rules/ directory.
Each rule is a YAML document that describes a security check.

The loader normalizes the rule schema so the engine can execute checks consistently.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Union

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT_DIR / "rules"


def load_rules(rules_path: Union[str, Path] = RULES_DIR) -> List[Dict[str, Any]]:
    """Load all rule definitions from the specified rules directory.

    Returns a list of normalized rule dictionaries.
    """

    rules: List[Dict[str, Any]] = []

    rules_path_obj = Path(rules_path) if isinstance(rules_path, str) else rules_path
    if not rules_path_obj.is_dir():
        return rules

    for filename in rules_path_obj.iterdir():
        if filename.suffix not in {".yaml", ".yml"}:
            continue

        with filename.open("r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)

        if not loaded:
            continue

        if isinstance(loaded, dict):
            loaded = [loaded]

        if not isinstance(loaded, list):
            continue

        for raw_rule in loaded:
            if not isinstance(raw_rule, dict):
                continue

            # Normalize keys for compatibility with older rule formats
            rule: Dict[str, Any] = {
                "id": raw_rule.get("id") or raw_rule.get("rule_id"),
                "title": raw_rule.get("title"),
                "severity": raw_rule.get("severity"),
                "cis_reference": raw_rule.get("cis_reference") or raw_rule.get("cis"),
                "resource_type": raw_rule.get("resource_type") or raw_rule.get("resource"),
                "check": raw_rule.get("check") or raw_rule.get("condition"),
                # allow additional metadata to pass through
                **{k: v for k, v in raw_rule.items() if k not in {"id", "rule_id", "title", "severity", "cis_reference", "cis", "resource_type", "resource", "check", "condition"}},
            }

            if not rule["id"] or not rule["resource_type"] or not rule["check"]:
                # Skip incomplete rules
                continue

            rules.append(rule)

    return rules
