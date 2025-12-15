from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import run_command
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation


class PasswordlessSudoCheck(Action):
    """
    List sudo commands.
    """

    def __init__(self):
        super().__init__(
            "PasswordlessSudoCheck", "T1069", "TA0007", ["quiet", "fast"]
        )
        self.noise = 0.5
        self.impact = 0.0
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for PasswordlessSudoCheck.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_PasswordlessSudoCheck",
            description="Input motif for PasswordlessSudoCheck"
        )
        input_motif.add_template(
            entity=Entity('Session', alias='session', active=True),
            template_name="existing_session",
            null_attributes=["listed_sudo_permissions"],
        )
        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for PasswordlessSudoCheck.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_PasswordlessSudoCheck",
            description="Output motif for PasswordlessSudoCheck"
        )

        output_motif.add_template(
            entity=Entity('Permission', alias='permission'),
            template_name="discovered_permission",
            relationship_type="has",
            match_on=Entity('User', alias='user'),
            invert_relationship=True,
        )

        output_motif.add_template(
            entity=Entity('Session', alias='session', listed_sudo_permissions=True),
            template_name="updated_session",
            operation=StateChangeOperation.UPDATE,
        )

        return output_motif


    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        session = pattern.get('session')._id
        return [f"Gain knowledge to change user in session ({session})"]

    def get_target_query(self) -> Query:
        """
        get_target_patterns check to find a session.
        """
        query = self.input_motif.get_query()
        query.where(self.input_motif.get_template('existing_session').entity.protocol.is_in(['ssh', 'busybox', 'shell']))
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Run sudo -l command in the session.
        """
        tulpa_session = pattern.get('session')
        tulpa_session_id = tulpa_session.get('id')
        live_session = sessions.get_session(tulpa_session_id)
        output = live_session.run_command("sudo -l")
        return ActionExecutionResult(command=["sudo -l"], stdout=output, session=tulpa_session_id)

    def parse_output(self, output: ActionExecutionResult) -> dict:
        """
        Parse the output of the action.
        """
        lines = output.stdout.strip().split("\n")
        discovered_permissions = []
        for line in lines:
            if "NOPASSWD" in line:
                sudo_usr = line.split(")")[0].strip()[1:]
                command = line.split("NOPASSWD:")[-1].strip()
                discovered_permissions.append({
                    'sudo_usr': sudo_usr,
                    'command': command
                })
        return discovered_permissions

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate the output motif with the discovered data.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        session = pattern.get('session')
        username = session.get('username')

        for discovered_permission in discovered_data:
            changes.append(self.output_motif.instantiate(
                template_name="discovered_permission",
                match_on_override=Entity('User', alias='user', username=username),
                name=discovered_permission['command'],
                command=discovered_permission['command'],
                as_user=discovered_permission['sudo_usr']
            ))

        changes.append(self.output_motif.instantiate(
            template_name="updated_session",
            match_on_override=session,
            listed_sudo_permissions=True
        ))
        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Update knowledge graph with the discovered command permissions.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes