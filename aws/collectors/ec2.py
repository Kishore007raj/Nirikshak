import json
from core.models import Resource


def collect_ec2_instances(region, profile):

    with open("demo_data/security_groups.json") as f:
        sgs = json.load(f)

    resources = []

    for sg in sgs:
        resources.append(
            Resource(
                resource_type="security_group",
                resource_id=sg["group_id"],
                region=region,
                config=sg
            )
        )

    return resources
