from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import run_command
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from Session import SessionManager


class PasswordlessSudoCheck(Action):
    """
    List sudo commands.
    """

    def __init__(self):
        super().__init__(
            "PasswordlessSudoCheck", "T1069 Permission Groups Discovery", "TA0007 Discovery", ["quiet", "fast"]
        )
        self.noise = 0.5
        self.impact = 0.0

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        session = pattern.get('session')._id
        return [f"Gain knowledge to change user in session ({session})"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check to find a session.
        """
        session = Entity(type='Session', alias='session')
        res = kg.match(session).where("""session.listed_sudo_permissions IS NULL""")
        ret = [p for p in res if p.get('session').get('protocol') in ['ssh', 'busybox']]
        return ret

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Run sudo -l command in the session.
        """
        session = pattern.get('session')
        session_id = session.get('id')
        channel = sessions.get_session(session_id)
        output = run_command(channel, "sudo -l")
        return ActionExecutionResult(command=["sudo -l"], stdout="\n".join(output), session=session_id)

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Update knowledge graph with the discovered command permissions.
        """
        session = pattern.get('session')
        user = session.get('username')
        lines = output.stdout.strip().split("\n")

        changes: StateChangeSequence = []
        for line in lines:
            if "NOPASSWD" in line:
                sudo_usr = line.split(")")[0].strip()[1:]
                command = line.split("NOPASSWD:")[-1].strip()
                user = Entity(type='User', alias='user', username=user)
                merge_pattern = user.with_edge(Relationship(type='has', direction='r')).with_node(
                    Entity(type='Permission', name=command, command=command, as_user=sudo_usr)
                )
                changes.append((user, "merge", merge_pattern))

        new_session = session.copy()
        new_session.set('listed_sudo_permissions', True)
        changes.append((session, "update", new_session))
        return changes