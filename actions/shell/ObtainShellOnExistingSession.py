from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionResult, ActionExecutionError
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation


class ObtainShellOnExistingSession(Action):
    """
    Using a session obtained via lateral movement on the target machine, spawn a shell session on the target.
    """

    def __init__(self):
        super().__init__(
            "ObtainShellOnExistingSession",
            "T1548",
            "TA0004",
            ["quiet", "fast"],
        )
        self.noise = 0.5
        self.impact = 0.2
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for ObtainShellOnExistingSession.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_ObtainShellOnExistingSession",
            description="Input motif for ObtainShellOnExistingSession"
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
            template_name="existing_service",
            entity=Entity('Service', alias='service'),
            relationship_type="is_running",
            match_on="existing_port",
            invert_relationship=True,
        )

        input_motif.add_template(
            template_name="existing_session",
            entity=Entity('Session', alias='session', protocol='msf', active=True),
            relationship_type="executes_on",
            match_on="existing_service",
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for ObtainShellOnExistingSession.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_ObtainShellOnExistingSession",
            description="Output motif for ObtainShellOnExistingSession"
        )

        output_motif.add_template(
            template_name="updated_session",
            entity=Entity('Session', alias='session', active=False),
            operation=StateChangeOperation.UPDATE,
            expected_attributes=['active'],
        )

        output_motif.add_template(
            entity=Entity('Session', alias='shell_session', protocol='shell', active=True),
            template_name="discovered_shell_session",
            relationship_type="executes_on",
            match_on=Entity('Service', alias='service')
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        session = pattern.get('session')
        service = pattern.get('service')
        port = pattern.get('port')
        asset = pattern.get('asset')
        return [f"Use session (id={session._id}) to spawn a shell process on the {service.get('protocol')} service exposed on {port.get('number')} on {asset.get('ip_address')}"]

    def get_target_query(self) -> Query:
        """
        get_target_patterns check to find a valid session
        """
        query = self.input_motif.get_query()
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Run shell command to spawn a shell process.
        """
        tulpa_session = pattern.get('session')
        tulpa_session_id = tulpa_session.get('id')
        live_session = sessions.get_session(tulpa_session_id)
        output = live_session.run_command("shell")
        return ActionExecutionResult(command=["shell"], stdout=output, session=tulpa_session_id)

    def parse_output(self, output: ActionExecutionResult, artefacts: ArtefactManager) -> dict:
        """
        Parse the output of the shell command.
        """
        return {
            'old_session_active': False,
            'shell_session_active': True,
        }

    def populate_output_motif(self, kg: GraphDB, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate the output motif with the discovered data.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        old_session = pattern.get('session')
        service = pattern.get('service')
        
        updated_session_change = self.output_motif.instantiate(
            template_name="updated_session",
            match_on_override=old_session,
            active=discovered_data['old_session_active'],
        )
        changes.append(updated_session_change)

        updated_session_pattern = updated_session_change[-1]
        if isinstance(updated_session_pattern, Pattern):
            updated_session_entity = updated_session_pattern.get('session')
        else:
            updated_session_entity = updated_session_pattern

        if isinstance(pattern, MultiPattern):
            match_pattern = (
                pattern[0] & pattern[1] & pattern[2] & updated_session_entity - Relationship('executes_on') - service
            )
        else:
            match_pattern = (
                pattern.get('asset') & pattern.get('port') & pattern.get('service') & updated_session_entity - Relationship('executes_on') - service
            )

        shell_session_change = self.output_motif.instantiate(
            template_name="discovered_shell_session",
            full_pattern_override=match_pattern,
            additional_relationships=[
                (
                    "spawned",
                    updated_session_entity,
                    True,
                ),
            ],
            active=discovered_data['shell_session_active'],
            protocol='shell',
            id=updated_session_entity.get('id'),
        )
        changes.append(shell_session_change)
        return changes

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Update knowledge graph to reflect the new shell session.
        """
        discovered_data = self.parse_output(output, artefacts)
        changes = self.populate_output_motif(kg, pattern, discovered_data)
        return changes