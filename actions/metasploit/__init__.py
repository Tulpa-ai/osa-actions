import os
import json
from .ExploitAction import ExploitAction


def get_actions() -> list:
    with open(f"{os.path.dirname(__file__)}/msfconfigs.json", "r") as f:
        configs = json.load(f)
        
        return [ExploitAction(name=config["name"], module_name=config["module_name"], cves=config["cves"], vuln_service=config.get("vuln_service")) for config in configs]
    