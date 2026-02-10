#this models file inside the core directory is used to define the data models for the application and it will contain all the classes and functions related to the data models of the application and in the future we will add more classes and functions related to the data models as we progress with the development of the application.

from dataclasses import dataclass
from typing import List, Dict, Any

#this code is written for defining the data model for the scan result and it will be used to store the scan results in a structured format and it will also be used to generate the report in the future.
@dataclass
class ScanResult:
    resource_id: str
    resource_type: str
    misconfigurations: List[Dict[str, Any]]
    region: str
    provider: str
