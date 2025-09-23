import xml.etree.ElementTree as ET
from xmlrpc.client import boolean

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import parse_nmap_xml_report, shell, query_scap_for_cve_fuzzy
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
    os_cpe = "unknown"
    
    # The previous := check here wasn't safe because Element objects are considered False if they have no children
    osmatch = root.find(".//osmatch")
    if osmatch is not None:
        os_version = osmatch.get("name", "unknown")
        osclass = osmatch.find(".//osclass")
        if osclass is not None:
            os_family = osclass.get("osfamily", "unknown")
        cpe = osmatch.find(".//cpe")
        if cpe is not None:
            os_cpe = cpe.text
    
    return os_version, os_family, os_cpe

# Supporting parser functions
def ftp_nmap_parser(ap_pattern: Pattern, parsed_info: dict, svc_kwargs: dict, conn = None) -> StateChangeSequence:
    anon_login = parsed_info["ftp_anon_login"]
    users = parsed_info["ftp_users"]
    service = Entity('Service', alias='service', anonymous_login=anon_login, **svc_kwargs)
    open_port = ap_pattern.get('openport')
    merge_pattern = open_port.with_edge(Relationship('is_running', direction='r')).with_node(service)
    changes: StateChangeSequence = [(ap_pattern, "merge", merge_pattern)]
    for username in users:
        usr_pattern = Entity('User', username=username).with_edge(Relationship('is_client')).with_node(service)
        changes.append((merge_pattern, "merge", usr_pattern))
        
    if svc_kwargs.get("cpe") and svc_kwargs["cpe"] != "unknown":
        cve_dict = query_scap_for_cve_fuzzy(svc_kwargs["cpe"], conn)
        for cve_id, details in cve_dict.items():
            vuln = Entity('Vulnerability', alias='vuln', id=cve_id, source=details[0], criteria=details[1])
            vuln_pattern = service.with_edge(Relationship('exposes', direction='r')).with_node(vuln)
            changes.append((service, "merge", vuln_pattern))
            
    return changes

def generic_service_parser(ap_pattern: Pattern, parsed_info: dict, svc_kwargs: dict, conn = None) -> StateChangeSequence:
    service = Entity('Service', alias='service', **svc_kwargs)
    open_port = ap_pattern.get('openport')
    merge_pattern = open_port.with_edge(Relationship('is_running')).with_node(service)
    changes = [(ap_pattern, "merge", merge_pattern)]
    
    if svc_kwargs.get("cpe") and svc_kwargs["cpe"] != "unknown":
        cve_dict = query_scap_for_cve_fuzzy(svc_kwargs["cpe"], conn)
        for cve_id, details in cve_dict.items():
            vuln = Entity('Vulnerability', alias='vuln', id=cve_id, source=details[0], criteria=details[1])
            vuln_pattern = service.with_edge(Relationship('exposes', direction='r')).with_node(vuln)
            changes.append((service, "merge", vuln_pattern))
                    
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
        result = shell("nmap", ["-Pn", "-sT", "-sV", "-O", "-p-", asset.get('ip_address'), "-oX", out_path])
        result.artefacts["xml_report"] = uuid
        return result

    def capture_state_change(self, gdb: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult, conn=None) -> StateChangeSequence:
        asset = pattern.get('asset')
        changes: StateChangeSequence = []
        try:
            with artefacts.open(output.artefacts["xml_report"], 'r') as f:
                content = f.read()
        except KeyError as e:
            raise ActionExecutionError(e)
        
        try:
            os_version, os_family, os_cpe = nmap_parse_os_version_and_family(content)
        except ET.ParseError as e:
            raise ActionExecutionError(e)
        asset = pattern.get('asset')
        asset.set('os_version', os_version)
        asset.set('os_family', os_family)
        asset.set('cpe', os_cpe)

        changes.append((pattern, 'update', asset))
        
        if os_cpe != "unknown":
            cves = query_scap_for_cve_fuzzy(os_cpe, conn)
            for cve in cves:
                vuln = Entity('Vulnerability', alias='vuln', id=cve)
                vuln_pattern = asset.with_edge(Relationship('exposes', direction='r')).with_node(vuln)
                changes.append((asset, "merge", vuln_pattern))
    
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
            
            cpe = port.get("cpe", "unknown")
            service_kwargs = {
                "protocol": service_name,
                "version": f"{product} {version}".strip(),
                "cpe": cpe
            }
            
            if f := self._parsers.get(service_name):
                parser_changes = f(merge_pattern, parsed_info, service_kwargs, conn)
                changes.extend(parser_changes)
            else:
                parser_changes = generic_service_parser(merge_pattern, parsed_info, service_kwargs, conn)
                changes.extend(parser_changes)

        return changes
