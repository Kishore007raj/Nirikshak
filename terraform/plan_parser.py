"""Terraform plan JSON parsing utilities."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from core.models import Resource


def parse_terraform_plan(plan_path: str) -> List[Resource]:
    """Parse a Terraform plan JSON file into normalized resources."""

    path = Path(plan_path)
    if not path.exists():
        raise FileNotFoundError(f"Terraform plan file not found: {plan_path}")

    with path.open("r", encoding="utf-8") as f:
        plan = json.load(f)

    resources: List[Resource] = []

    # Terraform plan structure: planned_values.root_module.resources
    root = plan.get("planned_values", {}).get("root_module", {})

    def _collect(module: Dict) -> None:
        for res in module.get("resources", []):
            res_type = res.get("type")
            res_name = res.get("name")
            address = res.get("address")
            values = res.get("values", {})

            resources.append(
                Resource(
                    resource_type=res_type or "terraform_resource",
                    resource_id=address or res_name or "",
                    region=values.get("region") or values.get("location") or "",
                    provider="terraform",
                    config=values,
                )
            )

        for child in module.get("child_modules", []):
            _collect(child)

    _collect(root)
    return resources
