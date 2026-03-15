"""AWS EC2 instance collectors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from core.models import Resource

ROOT_DIR = Path(__file__).resolve().parents[2]


def collect_ec2_instances(region: str, profile: Optional[str] = None, mode: str = "demo") -> List[Resource]:
    """Collect EC2/compute instances for scanning."""

    if mode == "demo":
        with open(ROOT_DIR / "demo_data" / "ec2_instances.json", "r", encoding="utf-8") as f:
            instances = json.load(f)

        resources: List[Resource] = []
        for inst in instances:
            resources.append(
                Resource(
                    resource_type="ec2_instance",
                    resource_id=inst.get("instance_id"),
                    region=region,
                    provider="aws",
                    config={
                        "public_ip": inst.get("public_ip"),
                        "disk_encrypted": inst.get("disk_encrypted"),
                        "security_groups": inst.get("security_groups", []),
                    },
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
        reservations = ec2.describe_instances().get("Reservations", [])
        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                resources.append(
                    Resource(
                        resource_type="ec2_instance",
                        resource_id=instance.get("InstanceId"),
                        region=region,
                        provider="aws",
                        config={
                            "public_ip": instance.get("PublicIpAddress"),
                            "disk_encrypted": all(
                                b.get("Encrypted", False)
                                for b in instance.get("BlockDeviceMappings", [])
                                if b.get("Ebs")
                            ),
                            "security_groups": instance.get("SecurityGroups", []),
                        },
                    )
                )
    except ClientError:
        pass

    return resources
