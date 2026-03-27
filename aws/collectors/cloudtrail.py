"""
CloudTrail collector.

Checks whether CloudTrail logging is enabled
for audit and compliance visibility.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from core.models import Resource

ROOT_DIR = Path(__file__).resolve().parents[2]


def collect_cloudtrail_trails(region: str, profile: Optional[str] = None, mode: str = "demo") -> List[Resource]:
    """Collect CloudTrail trail configurations."""

    if mode == "demo":
        with open(ROOT_DIR / "demo_data" / "aws" / "cloudtrail.json", "r", encoding="utf-8") as f:
            trails = json.load(f)

        resources: List[Resource] = []
        for trail in trails:
            resources.append(
                Resource(
                    resource_type="cloudtrail",
                    resource_id=trail.get("trail_name"),
                    region=region,
                    provider="aws",
                    config=trail,
                )
            )

        return resources

    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        raise RuntimeError("boto3 is required for real AWS scanning")

    session = boto3.Session(profile_name=profile, region_name=region)
    ct = session.client("cloudtrail")

    resources: List[Resource] = []

    try:
        resp = ct.describe_trails(includeShadowTrails=False)
        trails = resp.get("trailList", [])
    except ClientError:
        trails = []

    for trail in trails:
        resources.append(
            Resource(
                resource_type="cloudtrail",
                resource_id=trail.get("Name"),
                region=region,
                provider="aws",
                config={
                    "is_multi_region": trail.get("IsMultiRegionTrail"),
                    "s3_bucket": trail.get("S3BucketName"),
                },
            )
        )

    return resources
