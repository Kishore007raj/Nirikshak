"""
Strict Finding Normalization
Zero Failure Policy.
"""

from typing import Any, Dict, List
from utils.fallback import generate_description, generate_impact, generate_fix

def _format_compliance(compliance: Any) -> str:
    """Format compliance list into a strictly readable string."""
    if not compliance:
        return "CIS Benchmark"
    if isinstance(compliance, str):
        if compliance.strip() in ["", "-", "..."]:
            return "CIS Benchmark"
        return compliance.strip()
    
    parts = []
    if isinstance(compliance, list):
        for entry in compliance:
            if isinstance(entry, dict):
                fw = str(entry.get("framework", "")).strip()
                ctrl = str(entry.get("control_id", "")).strip()
                if fw and ctrl:
                    parts.append(f"{fw} {ctrl}")
                elif ctrl:
                    parts.append(ctrl)
            elif isinstance(entry, str):
                parts.append(entry.strip())
    
    res = ", ".join(filter(None, parts))
    return res if res else "CIS Benchmark"


def _clean(val: Any, default: str = "") -> str:
    if val is None:
        return default
    text = str(val).strip()
    if text in ["", "-", "...", "None"]:
        return default
    return text


def normalize_finding(f: Any) -> Dict[str, Any]:
    """Ensure every finding strictly matches Data Guarantee Phase 2."""
    
    if hasattr(f, "resource_id"):
        res_id = _clean(getattr(f, "resource_id", ""), "unknown-id")
        res_type = _clean(getattr(f, "resource_type", ""), _clean(getattr(f, "type", ""), "unknown-type"))
        sev = _clean(getattr(f, "severity", ""), "MEDIUM").upper()
        
        desc = _clean(getattr(f, "description", ""))
        imp = _clean(getattr(f, "impact", ""))
        fix = _clean(getattr(f, "fix_suggestion", ""))
        comp = getattr(f, "compliance", [])
    elif isinstance(f, dict):
        res_id = _clean(f.get("resource_id", ""), "unknown-id")
        res_type = _clean(f.get("resource_type", ""), _clean(f.get("type", ""), "unknown-type"))
        sev = _clean(f.get("severity", ""), "MEDIUM").upper()
        
        desc = _clean(f.get("description", ""))
        imp = _clean(f.get("impact", ""))
        fix = _clean(f.get("fix_suggestion", ""))
        comp = f.get("compliance", [])
    else:
        # Absolute fallback for invalid object types
        res_id, res_type, sev, desc, imp, fix, comp = "null", "null", "LOW", "", "", "", []
        
    desc = desc if desc else generate_description(res_type, sev)
    imp = imp if imp else generate_impact(res_type, sev)
    fix = fix if fix else generate_fix(res_type, sev)

    # Return strict format compliant with specs, merging the original finding attrs
    cleaned = {
        "resource_id": res_id,
        "type": res_type,  
        "resource_type": res_type,
        "severity": sev,
        "description": desc,
        "impact": imp,
        "fix_suggestion": fix,
        "compliance": _format_compliance(comp),
    }

    if isinstance(f, dict):
        return {**f, **cleaned}
    elif hasattr(f, "__dict__"):
        f_dict = f.__dict__.copy()
        # Ensure lists/dicts don't mutate unexpectedly
        return {**f_dict, **cleaned}
    return cleaned
