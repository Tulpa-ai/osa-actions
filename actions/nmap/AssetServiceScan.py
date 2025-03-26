import re
from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionError, ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, Pattern, Relationship, MultiPattern
from Session import SessionManager

# Supporting parser functions
def ftp_nmap_parser(gdb: GraphDB, ap_pattern: Pattern, nmap_output: list, svc_kwargs: dict) -> StateChangeSequence:
	ftp_section = re.search(r"21/tcp\s+open\s+ftp(.*?)MAC Address: ", nmap_output, re.DOTALL).group(1)
	anon_login = False
	users = []
	anon_login_pattern = r"Anonymous FTP login allowed"
	username_pattern = r"\d{2}:\d{2}\s+([^\s]+)$"
	for line in ftp_section.splitlines():
		if re.search(anon_login_pattern, line):
			anon_login = True
		if usr_search := re.search(username_pattern, line):
			users.append(usr_search.group(1))
	service = Entity('Service', alias='service', anonymous_login=anon_login, **svc_kwargs)
	open_port = ap_pattern.get('openport')
	merge_pattern = open_port.with_edge(Relationship('is_running', direction='r')).with_node(service)
	changes: StateChangeSequence = [(ap_pattern, "merge", merge_pattern)]
	for username in users:
		usr_pattern = Entity('User', username=username).with_edge(Relationship('is_client')).with_node(service)
		changes.append((merge_pattern, "merge", usr_pattern))
	return changes

def ssh_nmap_parser(gdb: GraphDB, ap_pattern: Pattern, nmap_output: list, svc_kwargs: dict) -> StateChangeSequence:
	service = Entity('Service', alias='service', **svc_kwargs)
	open_port = ap_pattern.get('openport')
	merge_pattern = open_port.with_edge(Relationship('is_running')).with_node(service)
	return [(ap_pattern, "merge", merge_pattern)]

def http_nmap_parser(gdb: GraphDB, ap_pattern: Pattern, nmap_output: list, svc_kwargs: dict) -> StateChangeSequence:
	service = Entity('Service', alias='service', **svc_kwargs)
	open_port = ap_pattern.get('openport')
	merge_pattern = open_port.with_edge(Relationship('is_running')).with_node(service)
	return [(ap_pattern, "merge", merge_pattern)]


class AssetServiceScan(Action):
	def __init__(self):
		super().__init__("AssetServiceScan", "T1046 Network Service Discovery", "TA0007 Discovery", ["loud", "fast"])
		self.noise = 0.9
		self.impact = 0
		self._parsers = {'ssh': ssh_nmap_parser, 'ftp': ftp_nmap_parser, 'http': http_nmap_parser}

	def expected_outcome(self, pattern: Pattern) -> list[str]:
		return [
			f"Gain knowledge of network services on {pattern.get('asset').get('ip_address')}. May include additional details for some services, such as indicating if anonymous FTP is supported.",
		]

	def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
		asset = Entity('Asset', alias='asset')
		return kg.get_matching(asset)

	def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
		asset = pattern.get('asset')
		result = shell("nmap", ["-Pn", "-sT", "-A", "--top-ports", "1000", asset.get('ip_address')])
		return result

	def capture_state_change(self, gdb: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult) -> StateChangeSequence:
		asset = pattern.get('asset')
		port_pattern_re = r"(\d+/tcp)\s+open"
		changes: StateChangeSequence = []
		for line in output.stdout.splitlines():
			if not (port_match := re.match(port_pattern_re, line)):
				continue
			num, protocol = port_match.group(1).split('/')
			open_port = Entity('OpenPort', alias='openport', number=int(num), protocol=protocol)
			merge_pattern = asset.with_edge(Relationship('has', direction='r')).with_node(open_port)
			changes.append((asset, "merge", merge_pattern))
			service_kwargs = {'protocol': line.split()[2], 'version': ' '.join(line.split()[3:])}
			if f := self._parsers.get(service_kwargs['protocol']):
				parser_changes = f(gdb, merge_pattern, output.stdout, service_kwargs)
				changes.extend(parser_changes)
		return changes