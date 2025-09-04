import pathlib
import re
from collections import defaultdict
from typing import Union
from ipaddress import ip_address

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import get_attack_ips, get_non_attack_ips, shell
from networking import is_ipv4_or_cidr
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, Pattern, Relationship, MultiPattern
from kg_api.query import Query
from Session import SessionManager

base_path = pathlib.Path(__file__).parent.parent.parent

class SlowNmapScan(Action):
    """
    Implementation of slow shallow NMAP scan.
    This NMAP scan is performed against subnets.
    """

    def __init__(self):
        super().__init__("SlowNmapScan", "T1046 Network Service Discovery", "TA0007 Discovery", ["quiet", "slow"])
        self.noise = 0.2
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
        get_target_patterns check for slow NMAP. This NMAP finds other assets on the
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
        NON_ATTACK_IPS = get_non_attack_ips(base_path / 'agent' / 'hard_bounds' / 'non_attack_ips.txt')
        ATTACK_IPS = get_attack_ips(base_path / 'agent' / 'hard_bounds' / 'attack_ips.txt')

        subnet = pattern.get('subnet')
        # Filter to only IPv4 addresses and CIDR ranges (Nmap can handle both)
        ip4_attack_ips = [ip for ip in ATTACK_IPS if is_ipv4_or_cidr(ip)]
        ip4_non_attack_ips = [ip for ip in NON_ATTACK_IPS if is_ipv4_or_cidr(ip)]

        if ATTACK_IPS:
            res = shell(
                "nmap",
                ["-T2", "-F", "-sS", "-n", " ".join(ip4_attack_ips)],
            )
            return res

        res = shell(
            "nmap",
            ["-T2", "-F", "-sS", "-n", subnet.get('network_address'), "--exclude", ",".join(ip4_non_attack_ips)],
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
            asset_pattern = gdb.get_matching(asset)
            
            if asset_pattern:
                asset = asset_pattern[0].get("asset")
                sub_match_pattern = subnet.combine(asset)
            else:
                sub_match_pattern = subnet
                
            sub_asset_pattern = asset.with_edge(Relationship('belongs_to')).with_node(subnet)
            
            changes.append((sub_match_pattern, "merge", sub_asset_pattern))
            for port in ports:
                num, protocol = port.split('/')
                port_pattern = asset.with_edge(Relationship('has')).with_node(
                    Entity('OpenPort', alias='port', number=int(num), protocol=protocol)
                )
                changes.append((sub_asset_pattern, "merge", port_pattern))

        return changes