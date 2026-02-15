#this engine file is used to run the rule engine and it will contain all the logic related to running the rule engine for the application.

def evaluate_condition(resource, rule):

    condition = rule["condition"]

    config = resource.config

    # S3 public access check
    if "public_access_block.BlockPublicAcls" in condition:
        value = config.get("public_access_block", {}).get("BlockPublicAcls", True)
        return value is False

    # Encryption check
    if "encryption_enabled" in condition:
        return config.get("encryption_enabled") is False

    # IAM MFA check
    if "mfa_enabled" in condition:
        return config.get("mfa_enabled") is False

    # CloudTrail multi-region
    if "is_multi_region" in condition:
        return config.get("is_multi_region") is False

    # Security Group SSH check
    if rule["resource"] == "security_group":
        for perm in config.get("inbound_rules", []):
            if perm.get("FromPort") == 22:
                for ip in perm.get("IpRanges", []):
                    if ip.get("CidrIp") == "0.0.0.0/0":
                        return True

    return False


def run_engine(resources, rules):

    findings = []

    for resource in resources:
        for rule in rules:
            # ensure rule is a dict and has a resource key
            if not isinstance(rule, dict):
                continue
            if resource.resource_type == rule.get("resource"):
                if evaluate_condition(resource, rule):
                    findings.append({
                        "rule_id": rule.get("id"),
                        "title": rule.get("title"),
                        "severity": rule.get("severity"),
                        "cis": rule.get("cis"),
                        "resource_id": resource.resource_id,
                        "resource_type": resource.resource_type,
                        "region": getattr(resource, "region", None),
                        "details": f"Matched condition: {rule.get('condition')}"
                    })

    return findings
