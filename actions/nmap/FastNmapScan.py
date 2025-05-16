import pathlib
import re
from collections import defaultdict
from typing import Union
from ipaddress import ip_address

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import get_attack_ips, get_non_attack_ips, shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, Pattern, Relationship, MultiPattern
from kg_api.query import Query
from Session import SessionManager

base_path = pathlib.Path(__file__).parent.parent.parent

class FastNmapScan(Action):
    """
    Implementation of shallow NMAP scan.
    This NMAP scan is performed against subnets.
    """

    def __init__(self):
        super().__init__("FastNmapScan", "T1046 Network Service Discovery", "TA0007 Discovery", ["loud", "fast"])
        self.noise = 0.8
        self.impact = 0

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        return [
            f"Gain knowledge of network hosts on {pattern.get('subnet').get('network_address')}",
            f"Gain knowledge of network services on {pattern.get('subnet').get('network_address')}",
        ]

    def get_target_query(self) -> Query:
        """
        get_target_patterns check for fast NMAP. This NMAP finds other assets on the
        network but does not identify open ports or services.
        """
        sub = Entity('Subnet', alias='subnet')
        query = Query()
        query.match(sub)
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use execute function from action_utils to perform NMAP scan.
        """
        NON_ATTACK_IPS = get_non_attack_ips(base_path / 'non_attack_ips.txt')
        ATTACK_IPS = get_attack_ips(base_path / 'attack_ips.txt')

        subnet = pattern.get('subnet')
        ip4_attack_ips = [ip for ip in ATTACK_IPS if ip_address(ip).version == 4]
        ip4_non_attack_ips = [ip for ip in NON_ATTACK_IPS if ip_address(ip).version == 4]

        if ATTACK_IPS:
            res = shell(
                "nmap",
                ["-F", "-sS", "-n", " ".join(ip4_attack_ips)],
            )
            return res

        res = shell(
            "nmap",
            ["-F", "-sS", "-n", subnet.get('network_address'), "--exclude", ",".join(ip4_non_attack_ips)],
        )
        return res

    def capture_state_change(
        self, gdb: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Add Asset entities and OpenPort entities to knowledge graph.
        """
        ip_pattern = r"Nmap scan report for (\d{1,3}(?:\.\d{1,3}){3})"
        port_pattern = r"(\d+/tcp)\s+open"

        results = defaultdict(list)
        current_ip = None

        for line in output.stdout.splitlines():
            ip_match = re.match(ip_pattern, line)
            if ip_match:
                current_ip = ip_match.group(1)
                results.setdefault(current_ip, [])
            elif current_ip:
                port_match = re.match(port_pattern, line)
                if port_match:
                    results[current_ip].append(port_match.group(1))

        subnet = pattern.get('subnet')

        changes: StateChangeSequence = []
        for ip, ports in results.items():
            asset = Entity('Asset', alias='asset', ip_address=ip)
            sub_asset_pattern = asset.with_edge(Relationship('belongs_to')).with_node(subnet)
            changes.append((subnet, "merge", sub_asset_pattern))
            for port in ports:
                num, protocol = port.split('/')
                port_pattern = asset.with_edge(Relationship('has')).with_node(
                    Entity('OpenPort', alias='port', number=int(num), protocol=protocol)
                )
                changes.append((sub_asset_pattern, "merge", port_pattern))

        return changes