"""
Extended EC2 instance collector.

Fetches detailed instance configuration
required for security rule evaluation.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from core.models import Resource

ROOT_DIR = Path(__file__).resolve().parents[2]


def collect_iam_users(region: str, profile: Optional[str] = None, mode: str = "demo") -> List[Resource]:
    """Collect IAM users and their security posture."""

    if mode == "demo":
        with open(ROOT_DIR / "demo_data" / "iam_users.json", "r", encoding="utf-8") as f:
            users = json.load(f)

        resources: List[Resource] = []
        for user in users:
            resources.append(
                Resource(
                    resource_type="iam_user",
                    resource_id=user.get("user_name"),
                    region=region,
                    provider="aws",
                    config=user,
                )
            )

        return resources

    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        raise RuntimeError("boto3 is required for real AWS scanning")

    session = boto3.Session(profile_name=profile, region_name=region)
    iam = session.client("iam")

    resources: List[Resource] = []

    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user.get("UserName")
                user_arn = user.get("Arn")
                mfa_enabled = False
                try:
                    mfas = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                    mfa_enabled = len(mfas) > 0
                except ClientError:
                    mfa_enabled = False

                # attached policies
                policies = []
                try:
                    attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
                    for p in attached:
                        policies.append(p.get("PolicyName") or "")
                except ClientError:
                    pass

                resources.append(
                    Resource(
                        resource_type="iam_user",
                        resource_id=username,
                        region=region,
                        provider="aws",
                        config={
                            "arn": user_arn,
                            "mfa_enabled": mfa_enabled,
                            "attached_policies": policies,
                        },
                    )
                )
    except ClientError:
        pass

    return resources
