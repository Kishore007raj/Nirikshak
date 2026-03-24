"""Rule evaluation engine.

The engine evaluates each normalized resource against the set of loaded rules.
Rules are expected to be normalized by `core.loader.load_rules`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from .models import Resource
from .severity import normalize_severity


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

    # AWS / Azure / GCP storage
    if resource.resource_type in {"s3_bucket", "storage_account", "gcs_bucket"}:
        # Public access checks
        pab = cfg.get("public_access_block") or {}
        facts["public_access_block.BlockPublicAcls"] = pab.get("BlockPublicAcls")
        facts["public_access_block.BlockPublicPolicy"] = pab.get("BlockPublicPolicy")
        facts["public_access_block.IgnorePublicAcls"] = pab.get("IgnorePublicAcls")
        facts["public_access_block.RestrictPublicBuckets"] = pab.get("RestrictPublicBuckets")
        
        # Azure storage account specific
        facts["public_access"] = cfg.get("public_access", False)
        facts["public_access_enabled"] = cfg.get("public_access", False)
        facts["allow_blob_public_access"] = cfg.get("public_access", False)
        facts["public_write"] = cfg.get("public_write", False)
        facts["firewall_enabled"] = cfg.get("firewall_enabled", True)
        facts["min_tls_version"] = cfg.get("min_tls_version", 1.2)
        facts["secure_transfer"] = cfg.get("secure_transfer", True)
        
        facts["encryption_enabled"] = cfg.get("encryption", cfg.get("encryption_enabled"))
        facts["versioning_enabled"] = cfg.get("versioning_enabled")

    # Network security group / firewall rules
    if resource.resource_type in {"security_group", "network_security_group", "firewall"}:
        inbound_rules = cfg.get("inbound_rules") or cfg.get("ip_permissions") or []
        facts["open_ssh"] = False
        facts["open_rdp"] = False
        facts["open_to_world"] = False
        facts["open_all_ports"] = False
        facts["wide_cidr"] = False

        for perm in inbound_rules:
            if isinstance(perm, dict):
                ports = []
                sources = []
                
                # AWS style (FromPort/ToPort)
                if isinstance(perm.get("FromPort"), int) and isinstance(perm.get("ToPort"), int):
                    ports = list(range(perm["FromPort"], perm["ToPort"] + 1))
                    cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", []) if r.get("CidrIp")]
                    sources.extend(cidrs)
                else:
                    # Generic/Azure style structure
                    port = perm.get("port")
                    if port:
                        try:
                            ports = [int(port) if isinstance(port, (int, str)) else port]
                        except (ValueError, TypeError):
                            ports = [port]
                    
                    source = perm.get("source") or perm.get("cidr") or perm.get("source_address_prefix")
                    if source:
                        sources = [source] if isinstance(source, str) else source

                # Check for open access
                for source in sources:
                    if source in {"0.0.0.0/0", "*", "0.0.0.0"}:
                        facts["open_to_world"] = True
                        if 22 in ports or "*" in ports:
                            facts["open_ssh"] = True
                        if 3389 in ports or "*" in ports:
                            facts["open_rdp"] = True
                    elif isinstance(source, str) and "/" in source:
                        try:
                            cidr_val = int(source.split("/")[1])
                            if cidr_val < 24:
                                facts["wide_cidr"] = True
                        except ValueError:
                            pass
                    
                    if "*" in ports or "Any" in ports or "any" in ports:
                        facts["open_all_ports"] = True
                    
            # Simplified check - if any source is world-open
            if isinstance(perm, dict):
                source = perm.get("source") or perm.get("cidr")
                if source in {"0.0.0.0/0", "*"}:
                    facts["open_to_world"] = True

        # Shorthand checks
        facts["open_all_ports"] = facts.get("open_to_world", False)

    # Compute / VM
    if resource.resource_type in {"ec2_instance", "virtual_machine", "vm", "compute_instance"}:
        facts["has_public_ip"] = bool(cfg.get("public_ip") or cfg.get("public_ip_address") or cfg.get("public_ips"))
        facts["disk_encrypted"] = cfg.get("disk_encrypted")
        facts["encryption_enabled"] = cfg.get("encryption_enabled")
        facts["ebs_encrypted"] = cfg.get("ebs_encrypted")
        facts["exposed_via_nsg"] = cfg.get("exposed_via_nsg", False)

    # Identity
    if resource.resource_type in {"iam_user", "azure_ad_user", "gcp_iam_user"}:
        facts["mfa_enabled"] = cfg.get("mfa_enabled")
        # Treat admin as any policy containing 'Administrator' or 'Owner'
        policies = cfg.get("attached_policies") or cfg.get("policies") or []
        facts["is_admin"] = any(
            isinstance(p, str) and any(k in p.lower() for k in ["admin", "owner"]) for p in policies
        )

    return facts


def run_engine(resources: List[Resource], rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run the rule engine for a list of normalized resources."""

    findings: List[Dict[str, Any]] = []
    now = datetime.utcnow().isoformat()

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
                # Evaluate simple expressions against facts + current config
                context = {**facts, **resource.config}
                try:
                    matched = _evaluate_expression(check, context)
                except Exception:
                    matched = False
            else:
                # Interpret check as a derived fact name
                matched = bool(facts.get(check))

            if matched:
                findings.append(
                    {
                        "rule_id": rule.get("id"),
                        "title": rule.get("title"),
                        "severity": severity,
                        "cis_reference": rule.get("cis_reference"),
                        "resource_id": resource.resource_id,
                        "resource_type": resource.resource_type,
                        "region": resource.region,
                        "provider": resource.provider,
                        "details": f"Rule '{rule.get('id')}' matched for resource '{resource.resource_id}'",
                        "timestamp": now,
                        "fix_suggestion": rule.get("fix_suggestion", ""),
                        "description": rule.get("description", ""),
                        "impact": rule.get("impact", ""),
                    }
                )

    return findings
