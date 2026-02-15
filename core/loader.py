#this loader file is used to load the configuration files and it will contain all the logic related to loading the configuration files for the application.

import yaml
import os

def load_rules():
    #Phase 3 will load YAML/JSON rules here and it will return the rules in a structured format to be used by the rule engine to run the scan and generate the report.
    
    rules = []
    rules_path = "rules"

    for file in os.listdir(rules_path):
        if file.endswith(".yaml") or file.endswith(".yml"):
            with open(os.path.join(rules_path, file), "r") as f:
                rule = yaml.safe_load(f)
                # YAML files may define a single rule (dict) or a list of rules.
                # Normalize to a flat list of rule dicts for the engine.
                if isinstance(rule, list):
                    rules.extend(rule)
                elif isinstance(rule, dict):
                    rules.append(rule)
                # ignore other types

    return rules