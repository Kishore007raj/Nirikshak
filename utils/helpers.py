"""
Helper utilities for Nirikshak.
"""
import json
from pathlib import Path
from typing import List
from core.models import Resource

def load_demo_data(provider: str) -> List[Resource]:
    """Load and normalize demo data for a given provider."""
    
    ROOT_DIR = Path(__file__).resolve().parents[1]
    demo_dir = ROOT_DIR / "demo_data" / provider
    
    if not demo_dir.is_dir():
        return []

    resources = []
    
    # Simple mapping from filename to normalized resource_type
    RESOURCE_MAP = {
        "aws": {
            "s3": "s3_bucket",
            "security_groups": "security_group",
            "ec2_instances": "ec2_instance",
            "iam_users": "iam_user",
            "cloudtrail": "cloudtrail",
        },
        "gcp": {
            "buckets": "gcs_bucket",
            "firewall": "firewall",
            "instances": "compute_instance",
        }
    }
    
    for filename in demo_dir.glob("*.json"):
        try:
            with open(filename, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    continue
                data = json.loads(content)
        except Exception:
            continue
            
        if not isinstance(data, list):
            data = [data]
            
        base_name = filename.stem
        # Try to resolve resource type from mapping, or fallback to the file name itself
        res_type = RESOURCE_MAP.get(provider, {}).get(base_name, base_name)
        
        for item in data:
            if not isinstance(item, dict):
                continue
                
            res_id = item.get("id") or item.get("name") or item.get("group_id") or f"{res_type}-demo"
            resources.append(
                Resource(
                    resource_type=res_type,
                    resource_id=res_id,
                    region="global",
                    provider=provider,
                    config=item
                )
            )
            
    return resources
