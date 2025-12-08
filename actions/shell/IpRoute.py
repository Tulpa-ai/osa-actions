import re
from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import run_command
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation


class IpRoute(Action):
    """
    Implementation of IP route.
    """

    def __init__(self):
        super().__init__(
            "IpRoute", "T1016", "TA0007", ["quiet", "fast"]
        )
        self.noise = 0.8
        self.impact = 0
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for IpRoute.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_IpRoute", description="Input motif for IpRoute"
        )

        input_motif.add_template(
            entity=Entity('Asset', alias='asset'),
            template_name="existing_asset",
        )

        input_motif.add_template(
            entity=Entity('OpenPort', alias='port'),
            template_name="existing_port",
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity('Service', alias='service'),
            template_name="existing_service",
            relationship_type="is_running",
            match_on="existing_port",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity('Session', alias='session'),
            template_name="existing_session",
            relationship_type="executes_on",
            match_on="existing_service",
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for IpRoute.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_IpRoute", description="Output motif for IpRoute"
        )

        output_motif.add_template(
            entity=Entity('Subnet', alias='subnet'),
            template_name="discovered_subnet",
            relationship_type="belongs_to",
            match_on=Entity('Asset', alias='asset'),
            invert_relationship=True,
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        return [f"Gain knowledge of network routes from {pattern.get('asset').get('ip_address')}"]

    def get_target_query(self) -> Query:
        """
        get_target_patterns check for IP route. This action finds other subnets that can be scanned.
        """
        # NB: this basic session type check will need to be removed when we do session management properly
        # matching_sessions = kg.match(session).where("NOT session.protocol IN ['rsh', 'ftp', 'msf']")
        # if not matching_sessions:
        #     return []

        # res = kg.match(match_pattern).where(
        #     f"id(service) IN {[s.get('session').get('executes_on') for s in matching_sessions]} AND NOT session.protocol IN ['rsh', 'ftp', 'msf']"
        # )

        query = self.input_motif.get_query()
        query.where_not(self.input_motif.get_template('existing_session').entity.protocol.is_in(['rsh', 'ftp', 'msf']))
        query.ret_all()
        return query

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

    def parse_output(self, output: ActionExecutionResult) -> dict:
        """
        Parse the output of the IpRoute action.
        """
        subnet_pattern = r'\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b'
        matches = re.findall(subnet_pattern, output.stdout)
        return {
            "discovered_network_addresses": matches
        }

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate the output motif for IpRoute.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        asset_to_match_on = pattern.get('asset')
        for network_address in discovered_data["discovered_network_addresses"]:
            changes.append(
                self.output_motif.instantiate(
                    template_name="discovered_subnet",
                    match_on_override=asset_to_match_on,
                    network_address=network_address
                )
            )
        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Read the target subnet from an environment variable instead of from the IP route tables.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes