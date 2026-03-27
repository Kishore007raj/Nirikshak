"""
Data models for Nirikshak.

Defines the core Resource, Finding, and ScanResult classes 
used across the entire pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Resource:
    """Represents a normalized cloud resource."""
    resource_type: str
    resource_id: str
    region: str
    config: Dict[str, Any]
    provider: str = "aws"

    @property
    def configuration(self) -> Dict[str, Any]:
        """Backward-compatible accessor for configuration data."""
        return self.config


@dataclass
class Finding:
    """Represents a single security violation detected by the engine."""
    rule_id: str
    title: str
    severity: str
    provider: str
    resource_id: str
    resource_type: str
    region: str
    timestamp: str
    description: str = ""
    impact: str = ""
    fix_suggestion: str = ""
    compliance: List[Dict[str, str]] = field(default_factory=list)
    cis_reference: str = ""
    details: str = ""
    # Metadata for risk scoring
    exposed_to_internet: bool = False
    sensitive_data: bool = False


@dataclass
class ScanResult:
    """Represents the complete result of a security scan."""
    scan_id: str
    provider: str
    mode: str
    timestamp: str
    resources: List[Resource] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    severity_count: Dict[str, int] = field(default_factory=dict)
    risk_score: int = 0
    compliance: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
