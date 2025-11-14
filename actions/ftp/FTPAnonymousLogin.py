from ftplib import FTP
from typing import Union
from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionResult
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif

class FTPAnonymousLogin(Action):
    def __init__(self):
        super().__init__("FTPAnonymousLogin", "T1078", "TA0001", ["quiet", "fast"])
        self.noise = 0.1
        self.impact = 0.6
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for FTPAnonymousLogin.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_FTPAnonymousLogin",
            description="Input motif for FTPAnonymousLogin"
        )

        input_motif.add_template(
            template_name="existing_asset",
            entity=Entity('Asset', alias='asset'),
        )

        input_motif.add_template(
            template_name="existing_port",
            entity=Entity('OpenPort', alias='port'),
            match_on="existing_asset",
            relationship_type="has",
            invert_relationship=True,
        )

        input_motif.add_template(
            template_name="existing_service",
            entity=Entity('Service', alias='service', protocol='ftp', anonymous_login=True),
            match_on="existing_port",
            relationship_type="is_running",
            invert_relationship=True,
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for FTPAnonymousLogin.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_FTPAnonymousLogin",
            description="Output motif for FTPAnonymousLogin"
        )

        output_motif.add_template(
            template_name="discovered_session",
            entity=Entity('Session', alias='session', protocol='ftp'),
            relationship_type="executes_on",
            match_on=Entity('Service', alias='service', protocol='ftp', anonymous_login=True),
            expected_attributes=["id"],
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        return [
            f"Gain a session on FTP service ({pattern.get('service')._id}) on {pattern.get('asset').get('ip_address')}"
        ]

    def function(self, sessions: SessionManager, artefacts, pattern: Pattern) -> ActionExecutionResult:
        asset = pattern.get('asset')
        ip_address = asset.get('ip_address')
        username, password = "anonymous", ""
        with FTP(host=ip_address, user=username, passwd=password):
            pass
        sess_id = sessions.add_session(
            {"protocol": "ftp", "host": ip_address, "username": username, "password": password}
        )
        return ActionExecutionResult(command=["AUTH", username], session=sess_id)

    def populate_output_motif(self, gdb: GraphDB, pattern: Pattern, discovered_data: dict) -> None:
        """
        Populate the output motif for FTPAnonymousLogin.
        """
        service = pattern.get('service')

        changes: StateChangeSequence = []
        session_change = self.output_motif.instantiate(
            template_name="discovered_session",
            match_on_override=service,
            protocol="ftp",
            id=discovered_data["session"],
        )
        changes.append(session_change)
        return changes
        
    def parse_output(self, output: ActionExecutionResult) -> dict:
        """
        Parse the output of the FTPAnonymousLogin action.
        """
        return {
            "session": output.session,
        }

    def capture_state_change(
        self, gdb: GraphDB, artefacts, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(gdb, pattern, discovered_data)
        return changes
