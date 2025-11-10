from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager


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

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        session = pattern.get('session')._id
        return [f"Use {session} to spawn a shell process on the target machine."]

    def get_target_query(self) -> Query:
        """
        get_target_patterns check to find a valid session
        """
        session = Entity(type='Session', alias='session', active=True)
        # res = kg.match(session).where("""session.listed_sudo_permissions IS NULL""")
        # ret = [p for p in res if p.get('session').get('protocol') in ['msf']]

        service = Entity(type='Service', alias='service')
        match_pattern = session.with_edge(Relationship('executes_on', direction='r')).with_node(service)

        query = Query()
        query.match(match_pattern)
        query.where(session.listed_sudo_permissions.is_null())
        query.where(session.protocol.is_in(['msf']))
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

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Update knowledge graph to reflect the new shell session.
        """
        session = pattern.get('session')
        service = pattern.get('service')

        update_session = session.copy()
        update_session.set('active', False)
        changes: StateChangeSequence = [(session, "update", update_session)]
        shell_session = Entity(
            'Session',
            alias='shell_session',
            protocol='shell',
            active=True,
            id=session.get('id'),
        )

        shell_session_with_service = shell_session.with_edge(Relationship('executes_on')).with_node(service)
        merge_pattern = update_session.with_edge(Relationship('spawned')).with_node(shell_session_with_service)
        changes.append((service, "merge", merge_pattern))
        return changes