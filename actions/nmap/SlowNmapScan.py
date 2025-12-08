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
from kg_api import Entity, Pattern, Relationship, MultiPattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif

base_path = pathlib.Path(__file__).parent.parent.parent

class SlowNmapScan(Action):
    """
    Implementation of slow shallow NMAP scan.
    This NMAP scan is performed against subnets.
    """

    def __init__(self):
        super().__init__("SlowNmapScan", "T1046", "TA0007", ["quiet", "slow"])
        self.noise = 0.2
        self.impact = 0
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for SlowNmapScan.

        Defines the required subnet entity that must exist for the scan to be applicable.

        Returns:
            ActionInputMotif: Input motif requiring a Subnet entity
        """
        input_motif = ActionInputMotif(
            name="InputMotif_SlowNmapScan",
            description="Input requirements for slow NMAP scan on subnet",
        )
        input_motif.add_template(
            entity=Entity('Subnet', alias='subnet'),
            template_name="subnet",
            expected_attributes=["network_address"]
        )
        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif templates for SlowNmapScan.

        Defines templates for:
        - Discovered assets (linked to subnet via belongs_to relationship)
        - Open ports (linked to assets via has relationship)

        Returns:
            ActionOutputMotif: Output motif with asset and port templates
        """
        subnet = Entity('Subnet', alias='subnet')

        output_motif = ActionOutputMotif(
            name="slow_nmap_scan_output",
            description="Templates for discovered assets and open ports (0-N instances each)"
        )

        output_motif.add_template(
            entity=Entity('Asset', alias='asset'),
            template_name="discovered_asset",
            match_on=subnet,
            relationship_type='belongs_to'
        )

        output_motif.add_template(
            entity=Entity('OpenPort', alias='port'),
            template_name="discovered_port",
            match_on="discovered_asset",
            relationship_type='has',
            invert_relationship=True
        )

        return output_motif

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
        query = self.input_motif.get_query()
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

    def parse_output(self, output: ActionExecutionResult) -> dict[str, list[str]]:
        """
        Parse NMAP output to extract discovered IP addresses and their open ports.
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

        return dict(results)

    def populate_output_motif(
        self, pattern: Pattern, discovered_data: dict[str, list[str]]
    ) -> StateChangeSequence:
        """
        Create state changes from parsed NMAP data using output motif templates.

        - Reset the output motif context for this execution
        - Get the actual subnet from the input pattern
        - Create a list of state changes
        - Instantiate the discovered_asset template with dynamic subnet matching
        - Instantiate the discovered_port template for each open port
        - Return the list of state changes
        
        Args:
            pattern: Pattern containing the subnet entity
            discovered_data: Dictionary mapping IP addresses to lists of open ports
            
        Returns:
            StateChangeSequence containing all state changes
        """
        self.output_motif.reset_context()
        subnet = pattern.get('subnet')
        changes: StateChangeSequence = []
        for ip, ports in discovered_data.items():
            asset_change = self.output_motif.instantiate(
                "discovered_asset", 
                match_on_override=subnet,
                ip_address=ip
            )
            changes.append(asset_change)
            
            for port in ports:
                num, protocol = port.split('/')
                port_change = self.output_motif.instantiate(
                    "discovered_port",
                    number=int(num),
                    protocol=protocol
                )
                changes.append(port_change)

        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Add Asset entities and OpenPort entities to knowledge graph.
        - Parse the NMAP output to extract discovered data
        - Create state changes from the parsed data
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
