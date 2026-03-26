import os
import yaml
from pathlib import Path

def add_compliance_to_rules(rules_dir="rules"):
    count = 0
    for root, _, files in os.walk(rules_dir):
        for file in files:
            if file.endswith((".yaml", ".yml")):
                path = Path(root) / file
                
                with open(path, "r", encoding="utf-8") as f:
                    docs = list(yaml.safe_load_all(f))
                
                changed = False
                for i in range(len(docs)):
                    doc = docs[i]
                    if isinstance(doc, list):
                        for j in range(len(doc)):
                            if isinstance(doc[j], dict) and "compliance" not in doc[j]:
                                cis_ref = doc[j].get("cis_reference") or doc[j].get("cis") or "CIS-General-1.1"
                                doc[j]["compliance"] = [
                                    {"framework": "CIS", "control_id": cis_ref},
                                    {"framework": "NIST", "control_id": "AC-3"}
                                ]
                                changed = True
                    elif isinstance(doc, dict):
                        if "compliance" not in doc:
                            cis_ref = doc.get("cis_reference") or doc.get("cis") or "CIS-General-1.1"
                            doc["compliance"] = [
                                {"framework": "CIS", "control_id": cis_ref},
                                {"framework": "NIST", "control_id": "AC-3"}
                            ]
                            changed = True
                            
                if changed:
                    with open(path, "w", encoding="utf-8") as f:
                        yaml.dump_all(docs, f, sort_keys=False, default_flow_style=False)
                    count += 1
                    print(f"Updated: {path}")
    print(f"Total files updated: {count}")

if __name__ == "__main__":
    add_compliance_to_rules()
