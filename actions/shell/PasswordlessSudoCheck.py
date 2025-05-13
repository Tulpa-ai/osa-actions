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

    def get_target_query(self) -> Query:
        """
        get_target_patterns check to find a session.
        """
        session = Entity(type='Session', alias='session')
        pattern = session.combine(Entity(type='Service', alias='service'))
        # res = kg.match(pattern).where("""session.listed_sudo_permissions IS NULL""")
        # ret = [p for p in res if p.get('session').get('protocol') in ['ssh', 'busybox', 'shell']]
        query = Query()
        query.match(pattern)
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
        service = pattern.get('service')
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
                elif service:
                    link_node = Entity(type='User', alias='user', username=sudo_usr)
                    merge_pattern = link_node.with_edge(Relationship(type='is_running', direction='r')).with_node(
                        service
                    )
                    changes.append((service, "merge", merge_pattern))

                    merge_pattern = link_node.with_edge(Relationship(type='has', direction='r')).with_node(
                        Entity(type='Permission', name=command, command=command, as_user=sudo_usr)
                    )
                    changes.append((link_node, "merge", merge_pattern))

                    update_session = session.copy()
                    update_session.set('username', sudo_usr)
                    changes.append((session, "update", update_session))

        new_session = session.copy()
        new_session.set('listed_sudo_permissions', True)
        changes.append((session, "update", new_session))
        return changes