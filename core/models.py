"""
Rule loader.

Parses YAML rule files and converts them
into executable rule objects.
"""

#this models file inside the core directory is used to define the data models for the application and it will contain all the classes and functions related to the data models of the application and in the future we will add more classes and functions related to the data models as we progress with the development of the application.

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Data models used across the Nirikshak pipeline.
# The Resource model represents a normalized cloud resource that can be evaluated by the rule engine.
@dataclass
class Resource:
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
    rule_id: str
    title: str
    severity: str
    provider: str
    resource_id: str
    resource_type: str
    region: str
    cis_reference: str
    timestamp: str
    details: str
    fix_suggestion: str = ""
    description: str = ""
    impact: str = ""
    compliance: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class ScanResult:
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
