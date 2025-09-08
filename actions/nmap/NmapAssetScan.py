import xml.etree.ElementTree as ET
from typing import Optional

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import parse_nmap_xml_report, shell
from action_state_interface.exec import ActionExecutionError, ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, Pattern, Relationship
from kg_api.query import Query
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

def add_vulnerability_entities(port, merge_pattern):
    changes = []
    if port["service"].get("vulnerabilities"):
        for vuln in port["service"]["vulnerabilities"]:
            vulnerability = Entity(
                'Vulnerability', 
                alias='vulnerability', 
                id=vuln["id"],
                cvss=vuln["cvss"],
                is_exploit=vuln["is_exploit"],
                vuln_type=vuln["type"]
            )
            vuln_merge_pattern = merge_pattern.with_edge(Relationship('exposes')).with_node(vulnerability)
            changes.append((merge_pattern, 'merge', vuln_merge_pattern))
    return changes

# Supporting parser functions
def ftp_nmap_parser(gdb: GraphDB, ap_pattern: Pattern, port_info: dict, parsed_info: dict, svc_kwargs: dict) -> StateChangeSequence:
    anon_login = parsed_info["ftp_anon_login"]
    users = parsed_info["ftp_users"]
    service = Entity('Service', alias='service', anonymous_login=anon_login, **svc_kwargs)
    open_port = ap_pattern.get('openport')
    merge_pattern = open_port.with_edge(Relationship('is_running', direction='r')).with_node(service)
    changes: StateChangeSequence = [(ap_pattern, "merge", merge_pattern)]
    for username in users:
        usr_pattern = Entity('User', username=username).with_edge(Relationship('is_client')).with_node(service)
        changes.append((merge_pattern, "merge", usr_pattern))
    changes.extend(add_vulnerability_entities(port_info, merge_pattern))
    return changes

def generic_service_parser(gdb: GraphDB, ap_pattern: Pattern, port_info: dict, nmap_output: list, svc_kwargs: dict) -> StateChangeSequence:
    service = Entity('Service', alias='service', **svc_kwargs)
    open_port = ap_pattern.get('openport')
    merge_pattern = open_port.with_edge(Relationship('is_running')).with_node(service)
    changes = [(ap_pattern, "merge", merge_pattern)]
    changes.extend(add_vulnerability_entities(port_info, merge_pattern))
    return changes


class NmapAssetScan(Action):
    def __init__(self):
        super().__init__("NmapAssetScan", "T1046", "TA0007", ["loud", "fast"])
        self.noise = 0.9
        self.impact = 0
        self._parsers = {'ftp': ftp_nmap_parser}

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        return [
            f"Gain knowledge of network services on {pattern.get('asset').get('ip_address')}. May include additional details for some services, such as indicating if anonymous FTP is supported.",
        ]

    def get_target_query(self) -> Query:
        asset = Entity('Asset', alias='asset')
        query = Query()
        query.match(asset)
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        asset = pattern.get('asset')
        uuid = artefacts.placeholder("nmap-asset-scan.xml")
        out_path = artefacts.get_path(uuid)
        result = shell("nmap", ["-Pn", "-sT", "-A", "--top-ports", "1000", "--script=vulners", "--script=banner", asset.get('ip_address'), "-oX", out_path])
        result.artefacts["xml_report"] = uuid
        return result

    def capture_state_change(self, gdb: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult) -> StateChangeSequence:
        asset = pattern.get('asset')
        changes: StateChangeSequence = []
        try:
            with artefacts.open(output.artefacts["xml_report"], 'r') as f:
                content = f.read()
        except KeyError as e:
            raise ActionExecutionError(e)
        
        try:
            os_version, os_family = nmap_parse_os_version_and_family(content)
        except ET.ParseError as e:
            raise ActionExecutionError(e)
        asset = pattern.get('asset')
        asset.set('os_version', os_version)
        asset.set('os_family', os_family)
        changes.append((pattern, 'update', asset))
    
        parsed_info = parse_nmap_xml_report(content)
        for port in parsed_info["ports"]:
            if port["state"] != "open":
                continue
            portid = port["portid"]
            protocol = port["protocol"]
            service_name = port["service"].get("name", "")
            product = port["service"].get("product", "")
            version = port["service"].get("version", "")
            open_port = Entity('OpenPort', alias='openport', number=int(portid), protocol=protocol)
            merge_pattern = asset.with_edge(Relationship('has', direction='r')).with_node(open_port)
            changes.append((asset, "merge", merge_pattern))

            banner = port["banner"]            
            if banner:
                open_port.set('banner', banner)
                changes.append((merge_pattern, "update", open_port))
                
            service_kwargs = {
                "protocol": service_name,
                "version": f"{product} {version}".strip()
            }
            if f := self._parsers.get(service_name):
                parser_changes = f(gdb, merge_pattern, port, parsed_info, service_kwargs)
                changes.extend(parser_changes)
            else:
                parser_changes = generic_service_parser(gdb, merge_pattern, port, parsed_info, service_kwargs)
                changes.extend(parser_changes)

        return changes
