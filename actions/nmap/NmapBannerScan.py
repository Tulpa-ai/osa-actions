import xml.etree.ElementTree as ET
from typing import Optional, Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionError, ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, Pattern, MultiPattern
from kg_api.query import Query
from Session import SessionManager

# Helper function for Banner extraction
def extract_banner_from_nmap_report_xml(xml_str) -> Optional[str]:
    root = ET.fromstring(xml_str)
    banner_script_element = root.find(".//script[@id='banner']")
    if banner_script_element is not None:
        banner = banner_script_element.get("output")
        if banner.isascii():
            return banner
    return None

class NmapBannerScan(Action):
    def __init__(self):
        super().__init__("NmapBannerScan", "T1046", "TA0007", ["loud", "fast"])
        self.noise = 0.2
        self.impact = 0

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        port_num = pattern.get("port").get("number")
        port_proto = pattern.get("port").get("protocol")
        return [f"Capture the banner for port {port_num}/{port_proto} on {pattern.get('asset').get('ip_address')}"]

    def get_target_query(self) -> Query:
        asset = Entity('Asset', alias='asset')
        port = Entity('OpenPort', alias='port')
        match_pattern = asset.directed_path_to(port)
        query = Query()
        query.match(match_pattern)
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        asset = pattern.get('asset')
        port = pattern.get("port")
        uuid = artefacts.placeholder("asset-banner-scan.xml")
        out_path = artefacts.get_path(uuid)
        res = shell("nmap", [
            "--script=banner",
            "--script-args", f"timeout=3,ports={port.get('number')}",
            asset.get("ip_address"),
            "-oX", out_path,
        ])
        res.artefacts["xml_report"] = uuid
        return res

    def capture_state_change(self, gdb: GraphDB, artefacts: ArtefactManager, pattern: Pattern,
                             output: ActionExecutionResult) -> StateChangeSequence:
        try:
            with artefacts.open(output.artefacts["xml_report"], 'r') as f:
                contents = f.read()
        except KeyError as e:
            raise ActionExecutionError(e)
        try:
            banner = extract_banner_from_nmap_report_xml(contents)
        except ET.ParseError as e:
            raise ActionExecutionError(e)
        changes: StateChangeSequence = []
        if banner:
            port = pattern.get("port")
            port.set('banner', banner)
            changes.append((pattern, "update", port))
        return changes