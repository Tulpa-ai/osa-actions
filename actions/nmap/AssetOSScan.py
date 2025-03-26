import xml.etree.ElementTree as ET
from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionError, ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, Pattern, Relationship, MultiPattern
from Session import SessionManager

# Helper function for OS scan parsing
def nmap_parse_os_version_and_family(xml_str):
    root = ET.fromstring(xml_str)
    os_version = "unknown"
    os_family = "unknown"
    if osmatch := root.find(".//osmatch"):
        os_version = osmatch.get("name", "unknown")
        if osclass := osmatch.find(".//osclass"):
            os_family = osclass.get("osfamily", "unknown")
    return os_version, os_family

class AssetOSScan(Action):
    def __init__(self):
        super().__init__("AssetOSScan", "T1046 Network Service Discovery", "TA0007 Discovery", ["loud", "fast"])
        self.noise = 0.2
        self.impact = 0

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        return [f"Gain knowledge of the OS on {pattern.get('asset').get('ip_address')}"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        asset = Entity('Asset', alias='asset')
        return kg.get_matching(asset)

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        asset = pattern.get('asset')
        uuid = artefacts.placeholder("asset-os-scan.xml")
        out_path = artefacts.get_path(uuid)
        res = shell("nmap", ["-O", asset.get('ip_address'), "-oX", out_path])
        res.artefacts["xml_report"] = uuid
        return res

    def capture_state_change(self, gdb: GraphDB, artefacts: ArtefactManager, pattern: Pattern,
                             output: ActionExecutionResult) -> StateChangeSequence:
        with artefacts.open(output.artefacts["xml_report"], 'r') as f:
            content = f.read()
        try:
            os_version, os_family = nmap_parse_os_version_and_family(content)
        except ET.ParseError as e:
            raise ActionExecutionError(e)
        asset = pattern.get('asset')
        asset.set('os_version', os_version)
        asset.set('os_family', os_family)
        return [(pattern, 'update', asset)]