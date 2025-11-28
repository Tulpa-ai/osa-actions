from ftplib import FTP
from typing import Union
from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionResult
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif

class FTPLoginWithCredentials(Action):
    def __init__(self):
        super().__init__("FTPLoginWithCredentials", "T1078", "TA0001", ["quiet", "fast"])
        self.noise = 0.0
        self.impact = 0.5
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for FTPLoginWithCredentials.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_FTPLoginWithCredentials",
            description="Input motif for FTPLoginWithCredentials"
        )
        
        input_motif.add_template(
            template_name="existing_asset",
            entity=Entity('Asset', alias='asset'),
        )

        input_motif.add_template(
            template_name="existing_port",
            entity=Entity('OpenPort', alias='port'),
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )

        input_motif.add_template(
            template_name="existing_service",
            entity=Entity('Service', alias='service', protocol='ftp'),
            relationship_type="is_running",
            match_on="existing_port",
            invert_relationship=True,
        )

        input_motif.add_template(
            template_name="existing_credentials",
            entity=Entity('Credentials', alias='credentials'),
            relationship_type="secured_with",
            match_on="existing_service"
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for FTPLoginWithCredentials.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_FTPLoginWithCredentials",
            description="Output motif for FTPLoginWithCredentials"
        )

        output_motif.add_template(
            template_name="discovered_session",
            entity=Entity('Session', alias='session', protocol='ftp'),
            relationship_type="executes_on",
            match_on=Entity('Service', alias='service', protocol='ftp'),
            expected_attributes=["id"],
        )
        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return a brief description of the expected outcome of the FTPLoginWithCredentials action.
        """
        ip = pattern.get('asset').get('ip_address')
        user = pattern.get('credentials').get('username')
        service = pattern.get('service')._id
        return [f"Gain a session on FTP service ({service}) on {ip} as user: {user}"]

    def get_target_query(self) -> Query:
        query = self.input_motif.get_query()
        query.where(self.input_motif.get_template('existing_credentials').entity.username != 'anonymous')
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts, pattern: Pattern) -> ActionExecutionResult:
        """
        Execute the FTPLoginWithCredentials action.
        """
        asset = pattern.get('asset')
        ip_address = asset.get('ip_address')
        creds = pattern.get('credentials')
        username = creds.get("username")
        password = creds.get("password")
        with FTP(host=ip_address, user=username, passwd=password):
            pass
        sess_id = sessions.add_session(
            {"protocol": "ftp", "host": ip_address, "username": username, "password": password}
        )
        return ActionExecutionResult(command=["USER", username, "PASS", password], session=sess_id)

    def parse_output(self, output: ActionExecutionResult) -> dict:
        """
        Parse the output of the FTPLoginWithCredentials action.
        """
        return {
            "session": output.session,
        }

    def populate_output_motif(self, kg: GraphDB, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate the output motif for FTPLoginWithCredentials.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []
        session_change = self.output_motif.instantiate(
            template_name="discovered_session",
            match_on_override=pattern.get('service'),
            protocol="ftp",
            id=discovered_data["session"],
        )
        changes.append(session_change)
        return changes

    def capture_state_change(
        self, kg: GraphDB, artefacts, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Capture the state change for the FTPLoginWithCredentials action.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(kg, pattern, discovered_data)
        return changes
