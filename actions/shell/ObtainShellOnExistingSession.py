from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from Session import SessionManager


class ObtainShellOnExistingSession(Action):
    """
    Using a session obtained via lateral movement on the target machine, spawn a shell session on the target.
    """

    def __init__(self):
        super().__init__(
            "ObtainShellOnExistingSession",
            "T1548 Abuse Elevation Control Mechanism",
            "TA0004 Privilege Escalation",
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

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check to find a valid session
        """
        session = Entity(type='Session', alias='session')
        res = kg.match(session).where("""session.listed_sudo_permissions IS NULL""")
        ret = [p for p in res if p.get('session').get('protocol') in ['msf']]
        return ret

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
        update_session = session.copy()
        update_session.set('active', False)
        changes: StateChangeSequence = [(session, "update", update_session)]
        shell_session = Entity(
            'Session',
            alias='shell_session',
            protocol='shell',
            active=True,
            executes_on=session.get('executes_on'),
            id=session.get('id'),
        )
        merge_pattern = update_session.with_edge(Relationship('spawned', direction='r')).with_node(shell_session)
        changes.append((update_session, "merge", merge_pattern))
        return changes