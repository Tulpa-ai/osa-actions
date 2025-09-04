from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import run_command
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager


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
        session = Entity(type='Session', alias='session')
        query = Query()
        query.match(session)
        query.where(session.listed_sudo_permissions.is_null())
        query.where(session.protocol.is_in(['ssh', 'busybox', 'shell']))
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
                if user:
                    link_node = Entity(type='User', alias='user', username=user)
                    merge_pattern = link_node.with_edge(Relationship(type='has', direction='r')).with_node(
                        Entity(type='Permission', name=command, command=command, as_user=sudo_usr)
                    )
                    changes.append((link_node, "merge", merge_pattern))

        new_session = session.copy()
        new_session.set('listed_sudo_permissions', True)
        changes.append((session, "update", new_session))
        return changes