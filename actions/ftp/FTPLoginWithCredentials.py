from ftplib import FTP
from typing import Union
from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionResult
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager

class FTPLoginWithCredentials(Action):
    def __init__(self):
        super().__init__("FTPLoginWithCredentials", "T1078", "TA0001", ["quiet", "fast"])
        self.noise = 0.0
        self.impact = 0.5

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        ip = pattern.get('asset').get('ip_address')
        user = pattern.get('credentials').get('username')
        service = pattern.get('service')._id
        return [f"Gain a session on FTP service ({service}) on {ip} as user: {user}"]

    def get_target_query(self) -> Query:
        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service', protocol='ftp')
        creds = Entity('Credentials', alias='credentials')
        pattern = (
            asset.with_edge(Relationship('has', direction='r'))
            .with_node(Entity('OpenPort'))
            .with_edge(Relationship('is_running', direction='r'))
            .with_node(service)
            .with_edge(Relationship('secured_with', direction='l'))
            .with_node(creds)
        )
        query = Query()
        query.match(pattern)
        query.where(creds.username != 'anonymous')
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts, pattern: Pattern) -> ActionExecutionResult:
        asset = pattern.get('asset')
        ip_address = asset.get('ip_address')
        creds = pattern.get('credentials')
        username = creds.get("username")
        password = creds.get("password")
        with FTP(host=ip_address, user=username, passwd=password):
            pass
        sess_id = sessions.add_session(
            {"protocol": "ftp", "host": ip_address, "username": username, "password": password}
        )
        return ActionExecutionResult(command=["USER", username, "PASS", password], session=sess_id)

    def capture_state_change(
        self, kg: GraphDB, artefacts, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        service = pattern.get('service')
        session = Entity('Session', alias='session', protocol='ftp', id=output.session)
        session_service_pattern = session.with_edge(Relationship('executes_on', direction='r')).with_node(service)
        return [(service, "merge", session_service_pattern)]