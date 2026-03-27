"""Rule evaluation engine.

The engine evaluates each normalized resource against the set of loaded rules.
Rules are expected to be normalized by `core.loader.load_rules`.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import Resource
from .severity import normalize_severity
from utils.time import get_ist_time


def _resolve_nested_key(data: Dict[str, Any], key_path: str) -> Any:
    """Resolve a dotted key path into a nested dictionary value.

    If the key itself includes dots (e.g., "public_access_block.BlockPublicAcls"), try
    direct lookup first before falling back to nested traversal.
    """

    if key_path in data:
        return data[key_path]

    current: Any = data
    for part in key_path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _to_python_literal(value: str) -> Any:
    """Convert a YAML-style literal into a Python literal."""
    v = str(value).strip()
    if v.lower() in {"true", "false"}:
        return v.lower() == "true"
    if v.lower() in {"null", "none"}:
        return None
    try:
        if "." in v:
            return float(v)
        return int(v)
    except ValueError:
        return v.strip('"').strip("'")


def _evaluate_expression(expression: str, context: Dict[str, Any]) -> bool:
    """Evaluate a simple left == right or left != right expression.

    Supports expressions like: "a.b == false" or "open_ssh == true".
    """

    if "==" in expression:
        left, right = expression.split("==", 1)
        op = "=="
    elif "!=" in expression:
        left, right = expression.split("!=", 1)
        op = "!="
    else:
        # Unsupported expression
        return False

    left = left.strip()
    right = right.strip()

    # Resolve left value from context
    value = _resolve_nested_key(context, left)
    expected = _to_python_literal(right)

    if op == "==":
        return value == expected
    return value != expected


def _compute_facts(resource: Resource) -> Dict[str, Any]:
    """Compute derived facts from a normalized resource for rule evaluation."""

    cfg = resource.config or {}
    facts: Dict[str, Any] = {}

    # ── Storage Resources ──────────────────────────────────────────────────
    if resource.resource_type in {"s3_bucket", "storage_account", "gcs_bucket"}:
        facts["sensitive_data"] = True
        
        # AWS style Public Access Block
        pab = cfg.get("public_access_block") or {}
        facts["public_access_block.BlockPublicAcls"] = pab.get("BlockPublicAcls")
        facts["public_access_block.BlockPublicPolicy"] = pab.get("BlockPublicPolicy")
        facts["public_access_block.IgnorePublicAcls"] = pab.get("IgnorePublicAcls")
        facts["public_access_block.RestrictPublicBuckets"] = pab.get("RestrictPublicBuckets")
        
        # Azure / GCP / Generic fields
        facts["public_access"] = cfg.get("public_access", cfg.get("public_access_enabled", False))
        facts["public_write"] = cfg.get("public_write", False)
        
        # Determine if broadly open to world
        facts["open_to_world"] = facts["public_access"] or (pab and not pab.get("BlockPublicPolicy", True))
        
        facts["encryption_enabled"] = cfg.get("encryption", cfg.get("encryption_enabled", False))
        facts["versioning_enabled"] = cfg.get("versioning_enabled", False)
        facts["firewall_enabled"] = cfg.get("firewall_enabled", True)

    # ── Network / Firewall ─────────────────────────────────────────────────
    if resource.resource_type in {"security_group", "network_security_group", "firewall"}:
        inbound_rules = cfg.get("inbound_rules") or cfg.get("ip_permissions") or []
        facts["open_ssh"] = False
        facts["open_rdp"] = False
        facts["open_to_world"] = False
        facts["open_all_ports"] = False

        for perm in inbound_rules:
            if isinstance(perm, dict):
                ports = []
                sources = []
                
                # AWS style (FromPort/ToPort)
                from_p = perm.get("FromPort")
                to_p = perm.get("ToPort")
                if isinstance(from_p, int) and isinstance(to_p, int):
                    ports = list(range(from_p, to_p + 1))
                    cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", []) if r.get("CidrIp")]
                    sources.extend(cidrs)
                else:
                    # Azure / Terraform style
                    port = perm.get("port") or perm.get("destination_port_range")
                    if port:
                        if port == "*" or str(port).lower() == "any":
                            ports = ["*"]
                        else:
                            try:
                                if "-" in str(port):
                                    start, end = str(port).split("-")
                                    ports = list(range(int(start), int(end) + 1))
                                else:
                                    ports = [int(port)]
                            except (ValueError, TypeError):
                                ports = [port]
                    
                    source = perm.get("source") or perm.get("cidr") or perm.get("source_address_prefix")
                    if source:
                        if isinstance(source, list):
                            sources.extend(source)
                        else:
                            sources.append(source)

                # Check for open access
                for src in sources:
                    is_world = src in {"0.0.0.0/0", "*", "0.0.0.0", "Internet", "any"}
                    if is_world:
                        facts["open_to_world"] = True
                        if 22 in ports or "*" in ports:
                            facts["open_ssh"] = True
                        if 3389 in ports or "*" in ports:
                            facts["open_rdp"] = True
                        if "*" in ports:
                            facts["open_all_ports"] = True

        facts["exposed_to_internet"] = facts["open_to_world"]

    # ── Compute / VM ───────────────────────────────────────────────────────
    if resource.resource_type in {"ec2_instance", "virtual_machine", "vm", "compute_instance"}:
        has_pub = bool(cfg.get("public_ip") or cfg.get("public_ip_address") or cfg.get("public_ips"))
        facts["has_public_ip"] = has_pub
        facts["exposed_to_internet"] = has_pub
        facts["disk_encrypted"] = cfg.get("disk_encrypted", cfg.get("encryption_enabled", False))
        facts["exposed_via_nsg"] = cfg.get("exposed_via_nsg", False)

    # ── Identity ───────────────────────────────────────────────────────────
    if resource.resource_type in {"iam_user", "azure_ad_user", "gcp_iam_user"}:
        facts["mfa_enabled"] = cfg.get("mfa_enabled", False)
        policies = cfg.get("attached_policies") or cfg.get("policies") or []
        facts["is_admin"] = any(
            isinstance(p, str) and any(k in p.lower() for k in ["admin", "owner"]) for p in policies
        )

    return facts


def run_engine(resources: List[Resource], rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run the rule engine for a list of normalized resources."""

    findings: List[Dict[str, Any]] = []
    now = get_ist_time()

    for resource in resources:
        facts = _compute_facts(resource)
        for rule in rules:
            if resource.resource_type != rule.get("resource_type"):
                continue

            severity = normalize_severity(rule.get("severity"))
            check = rule.get("check")
            if not check:
                continue

            matched = False
            if "==" in check or "!=" in check:
                context = {**facts, **resource.config}
                try:
                    matched = _evaluate_expression(check, context)
                except Exception:
                    matched = False
            else:
                matched = bool(facts.get(check))

            if matched:
                findings.append(
                    {
                        "rule_id": rule.get("id"),
                        "title": rule.get("title"),
                        "severity": severity,
                        "resource_id": resource.resource_id,
                        "resource_type": resource.resource_type,
                        "region": resource.region,
                        "provider": resource.provider,
                        "timestamp": now,
                        "description": rule.get("description", ""),
                        "impact": rule.get("impact", ""),
                        "fix_suggestion": rule.get("fix_suggestion", ""),
                        "compliance": rule.get("compliance", []),
                        # Metadata for risk scoring
                        "exposed_to_internet": facts.get("exposed_to_internet", False),
                        "sensitive_data": facts.get("sensitive_data", False),
                    }
                )

    return findings
