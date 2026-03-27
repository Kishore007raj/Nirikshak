"""
Context-aware fallback generators for Nirikshak findings.

These produce realistic, resource-type-specific text when rule definitions
do not supply description, impact, or fix_suggestion.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Mapping tables: resource_type -> context text
# ---------------------------------------------------------------------------

_DESCRIPTIONS: dict[str, str] = {
    "s3_bucket": "S3 bucket is misconfigured with insecure access or encryption settings, violating cloud storage security best practices.",
    "security_group": "Security group contains overly permissive inbound rules that expose associated resources to unauthorized network access.",
    "ec2_instance": "EC2 instance has a configuration that increases its attack surface, such as a public IP or unencrypted disks.",
    "iam_user": "IAM user account has insecure identity settings such as missing MFA or overly broad permissions.",
    "cloudtrail": "CloudTrail configuration does not meet security monitoring best practices, reducing visibility into API activity.",
    "storage_account": "Azure Storage Account has misconfigured access controls or encryption settings, exposing stored data to risk.",
    "network_security_group": "Network Security Group allows overly permissive traffic rules that expose Azure resources to the internet.",
    "vm": "Azure Virtual Machine has a security misconfiguration such as unencrypted disks or exposure via public NSG rules.",
    "azure_ad_user": "Azure AD user account is missing critical identity protections like MFA or has over-permissive role assignments.",
    "gcs_bucket": "GCS bucket is misconfigured with public access or missing encryption, violating cloud storage security best practices.",
    "firewall": "GCP firewall rule permits overly broad traffic that exposes compute resources to unauthorized access from the internet.",
    "compute_instance": "GCP Compute instance has a configuration that increases its attack surface, such as a public IP or unencrypted disks.",
    "gcp_iam_user": "GCP IAM principal has insecure identity settings such as missing MFA or over-broad permissions.",
}

_IMPACTS: dict[str, dict[str, str]] = {
    "CRITICAL": {
        "s3_bucket": "Complete data exposure to the public internet, enabling mass data exfiltration.",
        "security_group": "All ports or critical services are reachable from any IP, enabling full system compromise.",
        "ec2_instance": "Instance is directly attackable from the internet, risking full system takeover.",
        "iam_user": "Compromised admin credentials grant unrestricted access to the entire AWS environment.",
        "storage_account": "Publicly writable storage may be exploited for data tampering or ransomware staging.",
        "network_security_group": "All ports open to the internet, enabling direct attacks on associated Azure resources.",
        "vm": "Virtual machine is exposed through NSG rules allowing direct internet attacks on critical services.",
        "gcs_bucket": "Public bucket access allows anyone on the internet to exfiltrate all stored data.",
        "firewall": "Overly permissive firewall rule exposes all associated GCP compute resources to direct internet attacks.",
        "compute_instance": "Compute instance is directly reachable and exploitable from any internet source.",
    },
    "HIGH": {
        "s3_bucket": "Sensitive data may be accessed by unauthorized parties through misconfigured bucket policies.",
        "security_group": "Critical services like SSH or RDP are exposed to brute-force and exploitation attacks.",
        "ec2_instance": "Instance has elevated risk of unauthorized access through exposed network interfaces.",
        "iam_user": "Missing MFA allows credential-based account takeover without secondary verification.",
        "storage_account": "Unencrypted storage exposes data at rest to interception if access controls are bypassed.",
        "network_security_group": "SSH or RDP ports are open to the internet, enabling credential-based attacks.",
        "vm": "Unencrypted VM disks risk data exposure if snapshots or disks are shared or compromised.",
        "azure_ad_user": "Missing MFA on Azure AD account enables credential-based account takeover.",
        "gcs_bucket": "Bucket encryption gap reduces control over data protection and key lifecycle management.",
        "firewall": "SSH or RDP ports are reachable from the internet, enabling brute-force access attempts.",
        "compute_instance": "Public IP assignment makes the instance a target for scanning and exploitation.",
    },
    "MEDIUM": {
        "s3_bucket": "Weakened encryption controls reduce protection of stored data against advanced threats.",
        "security_group": "Moderately permissive network rules increase the potential attack surface.",
        "ec2_instance": "Unencrypted disks create risk of data exposure in snapshot or volume sharing scenarios.",
        "iam_user": "Insufficient identity controls weaken the overall security posture of the account.",
        "cloudtrail": "Limited logging coverage creates blind spots in security monitoring and incident response.",
        "storage_account": "Missing firewall rules or weak TLS versions expose the storage account to network-level threats.",
        "network_security_group": "Wide CIDR ranges in inbound rules increase the number of potential attack sources.",
        "vm": "VM configuration weaknesses may be exploited in combination with other vulnerabilities.",
        "azure_ad_user": "Over-permissive role assignment enables privilege escalation within the Azure environment.",
        "gcs_bucket": "Missing versioning prevents recovery from accidental or malicious data deletion.",
        "firewall": "Broad source IP ranges in firewall rules increase the potential for unauthorized access.",
        "compute_instance": "Unencrypted compute disks create risk of data exposure during disposal or sharing.",
    },
    "LOW": {
        "default": "Minor configuration weakness that should be reviewed to strengthen overall security posture.",
    },
}

_FIXES: dict[str, str] = {
    "s3_bucket": "Review and harden S3 bucket configuration: enable Public Access Block, server-side encryption, and object versioning.",
    "security_group": "Restrict security group inbound rules to specific trusted CIDR ranges and required ports only.",
    "ec2_instance": "Remove public IP, enable EBS encryption, and place the instance behind a load balancer or NAT gateway.",
    "iam_user": "Enable MFA, remove administrator-level policies, and apply least-privilege IAM permissions.",
    "cloudtrail": "Enable multi-region CloudTrail logging and configure log file validation with S3 bucket encryption.",
    "storage_account": "Disable public access, enable encryption and HTTPS-only transfer, and configure virtual network firewall rules.",
    "network_security_group": "Restrict NSG inbound rules to specific source IP ranges and required destination ports.",
    "vm": "Enable Azure Disk Encryption, remove public IP exposure, and restrict associated NSG rules.",
    "azure_ad_user": "Enable MFA via Conditional Access and use Privileged Identity Management for admin role assignments.",
    "gcs_bucket": "Remove public IAM bindings, enable Uniform Bucket-Level Access, configure CMEK, and enable versioning.",
    "firewall": "Restrict firewall rules to specific source IP ranges and required destination ports only.",
    "compute_instance": "Remove public IP, enable customer-managed disk encryption, and use Cloud NAT for egress.",
    "gcp_iam_user": "Enforce MFA and use least-privilege IAM roles with time-bound access via Workload Identity.",
}


def generate_description(resource_type: str, severity: str = "MEDIUM") -> str:
    """Return a context-aware description based on resource_type."""
    return _DESCRIPTIONS.get(
        resource_type,
        f"{resource_type} is misconfigured and violates security best practices for its resource category.",
    )


def generate_impact(resource_type: str, severity: str = "MEDIUM") -> str:
    """Return a severity- and resource-type-specific impact statement."""
    sev = severity.upper() if severity else "MEDIUM"
    sev_map = _IMPACTS.get(sev, _IMPACTS.get("LOW", {}))
    result = sev_map.get(resource_type)
    if result:
        return result
    # Fallback through severity hierarchy
    for fallback_sev in ["MEDIUM", "HIGH", "LOW"]:
        fb = _IMPACTS.get(fallback_sev, {})
        result = fb.get(resource_type) or fb.get("default")
        if result:
            return result
    return "This misconfiguration weakens the security posture and should be remediated."


def generate_fix(resource_type: str, severity: str = "MEDIUM") -> str:
    """Return a resource-type-specific fix suggestion."""
    return _FIXES.get(
        resource_type,
        f"Review the configuration of {resource_type} and apply least-privilege access controls and encryption best practices.",
    )
