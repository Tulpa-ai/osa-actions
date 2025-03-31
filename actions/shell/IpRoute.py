import re
from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import run_command
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from Session import SessionManager


class IpRoute(Action):
    """
    Implementation of IP route.
    """

    def __init__(self):
        super().__init__(
            "IpRoute", "T1016 System Network Configuration Discovery", "TA0007 Discovery", ["quiet", "fast"]
        )
        self.noise = 0.8
        self.impact = 0

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        return [f"Gain knowledge of network routes from {pattern.get('asset').get('ip_address')}"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check for IP route. This action finds other subnets that can be scanned.
        """
        session = Entity('Session', alias='session')
        # NB: this basic session type check will need to be removed when we do session management properly
        matching_sessions = kg.match(session).where("NOT session.protocol IN ['rsh', 'ftp', 'msf']")
        if not matching_sessions:
            return []

        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service')
        match_pattern = (
            asset.with_edge(Relationship('has'))
            .with_node(Entity('OpenPort', alias='openport'))
            .with_edge(Relationship('is_running'))
            .with_node(service)
            .combine(session)
        )

        res = kg.match(match_pattern).where(
            f"id(service) IN {[s.get('session').get('executes_on') for s in matching_sessions]} AND NOT session.protocol IN ['rsh', 'ftp', 'msf']"
        )
        return res

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use execute ip route.
        """
        tulpa_session = pattern.get('session')
        tulpa_session_id = tulpa_session.get('id')
        live_session = sessions.get_session(tulpa_session_id)
        output = live_session.run_command("ip route")
        exit_status = 1 if "ip: not found" in output else 0
        result = ActionExecutionResult(
            command=["ip", "route"], stdout="".join(output), exit_status=exit_status, session=tulpa_session_id
        )
        return result

    def capture_state_change(
        self, gdb: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Read the target subnet from an environment variable instead of from the IP route tables.
        """
        ip = pattern.get('asset').get('ip_address')
        subnet_pattern = r'\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b'
        matches = re.findall(subnet_pattern, output.stdout)
        changes: StateChangeSequence = []
        for match in matches:
            asset = Entity('Asset', alias='asset', ip_address=ip)
            subnet = Entity('Subnet', alias='subnet', network_address=match)
            sub_asset_pattern = asset.with_edge(Relationship('belongs_to')).with_node(subnet)
            changes.append((asset, "merge", sub_asset_pattern))
        return changes