#this engine file is used to run the rule engine and it will contain all the logic related to running the rule engine for the application.

from datetime import datetime

def evaluate_condition(resource, rule):

    config = resource.config

    # S3 public access
    if rule["resource"] == "s3_bucket":
        if "public_access_block.BlockPublicAcls" in rule["condition"]:
            value = config.get("public_access_block", {}).get("BlockPublicAcls", True)
            if value is False:
                return "public_access_block.BlockPublicAcls == false"

        if "encryption_enabled" in rule["condition"]:
            if config.get("encryption_enabled") is False:
                return "encryption_enabled == false"

    # Security Group SSH
    if rule["resource"] == "security_group":
        for perm in config.get("inbound_rules", []):
            if perm.get("FromPort") == 22:
                for ip in perm.get("IpRanges", []):
                    if ip.get("CidrIp") == "0.0.0.0/0":
                        return "SSH open to 0.0.0.0/0"

    # IAM MFA
    if rule["resource"] == "iam_user":
        if config.get("mfa_enabled") is False:
            return "mfa_enabled == false"

    # CloudTrail multi-region
    if rule["resource"] == "cloudtrail":
        if config.get("is_multi_region") is False:
            return "is_multi_region == false"

    return None


def run_engine(resources, rules):

    findings = []

    for resource in resources:
        for rule in rules:
            if resource.resource_type == rule["resource"]:

                match = evaluate_condition(resource, rule)

                if match:
                    findings.append({
                        "rule_id": rule["id"],
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "cis": rule["cis"],
                        "resource_id": resource.resource_id,
                        "resource_type": resource.resource_type,
                        "region": resource.region,
                        "details": f"Matched condition: {match}",
                        "detected_at": datetime.utcnow().isoformat()
                    })

    return findings
