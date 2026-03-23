"""
EC2 collector.

Retrieves EC2 instance metadata including:
- instance IDs
- security groups
- public IP exposure
- monitoring configuration
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from core.models import Resource

ROOT_DIR = Path(__file__).resolve().parents[2]


def collect_security_groups(region: str, profile: Optional[str] = None, mode: str = "demo") -> List[Resource]:
    """Collect security groups and normalize inbound rules."""

    if mode == "demo":
        with open(ROOT_DIR / "demo_data" / "aws" / "security_groups.json", "r", encoding="utf-8") as f:
            sgs = json.load(f)

        resources: List[Resource] = []
        for sg in sgs:
            resources.append(
                Resource(
                    resource_type="security_group",
                    resource_id=sg.get("group_id"),
                    region=region,
                    provider="aws",
                    config=sg,
                )
            )

        return resources

    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        raise RuntimeError("boto3 is required for real AWS scanning")

    session = boto3.Session(profile_name=profile, region_name=region)
    ec2 = session.client("ec2")

    resources: List[Resource] = []
    try:
        resp = ec2.describe_security_groups()
        groups = resp.get("SecurityGroups", [])
    except ClientError:
        groups = []

    for sg in groups:
        resources.append(
            Resource(
                resource_type="security_group",
                resource_id=sg.get("GroupId"),
                region=region,
                provider="aws",
                config={
                    "group_name": sg.get("GroupName"),
                    "description": sg.get("Description"),
                    "inbound_rules": sg.get("IpPermissions", []),
                },
            )
        )

    return resources
