import os
from typing import Union
from pathlib import Path
from ftplib import FTP, error_perm
from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionError, ActionExecutionResult
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager

def download_file(ftp, remote_file_path, local_file_path):
    items = []
    ftp.retrlines(f'LIST -a {remote_file_path}', items.append)
    if not items:
        ftp.retrlines(f'LIST -a /home{remote_file_path}', items.append)
        remote_file_path = f"/home{remote_file_path}"
    if not items:
        ftp.retrlines(f'LIST -a ~{remote_file_path}', items.append)
        remote_file_path = f"~{remote_file_path}"
    with open(local_file_path, 'wb') as local_file:
        ftp.retrbinary(f"RETR {remote_file_path}", local_file.write)

class FtpDownloadFile(Action):
    def __init__(self):
        super().__init__("FtpDownloadFile", "T1083", "TA0007", ["quiet", "fast"])
        self.noise = 0.2
        self.impact = 0.8

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        filename = pattern.get('path')[-1].get('filename')
        ip = pattern.get('asset').get('ip_address')
        session = pattern.get('session')._id
        service = pattern.get('service')._id
        return [f"Download file {filename} from FTP service ({service}) on {ip} using session ({session})"]

    def get_target_query(self) -> Query:
        session = Entity('Session', alias='session', protocol='ftp')
        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service', protocol='ftp')
        drive = Entity('Drive', alias='drive')
        service_pattern = (
            asset.with_edge(Relationship('has'))
            .with_node(Entity('OpenPort', alias='openport'))
            .with_edge(Relationship('is_running'))
            .with_node(service)
            .connects_to(drive)
        )
        file_pattern = drive.directed_path_to(Entity('File', alias='file'))
        file_pattern.set_alias('path')
        match_pattern = service_pattern.combine(file_pattern).combine(session)
        query = Query()
        query.match(match_pattern)
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts, pattern: Pattern) -> ActionExecutionResult:
        session = pattern.get('session')
        session_id = session.get('id')
        ftp_connection_details: dict = sessions.get_session(session_id)
        hostname = ftp_connection_details["host"]
        username = ftp_connection_details["username"]
        password = ftp_connection_details["password"]
        path_pattern: Pattern = pattern.get('path')
        ftp_path = Path('/')
        for g_obj in path_pattern:
            if g_obj.type == 'Directory':
                ftp_path = ftp_path / g_obj.get('dirname')
            if g_obj.type == 'File':
                ftp_path = ftp_path / g_obj.get('filename')
        with FTP(host=hostname, user=username, passwd=password) as ftp_session:
            uuid = artefacts.placeholder(ftp_path.name)
            local_path = artefacts.get_path(uuid)
            try:
                download_file(ftp_session, ftp_path, local_path)
            except error_perm:
                raise ActionExecutionError("File can't be downloaded")
            os.chmod(local_path, 0o600)
        return ActionExecutionResult(
            command=["GET", f"{ftp_path}"], session=session_id, artefacts={"downloaded_file_id": uuid}
        )

    def capture_state_change(
        self, kg: GraphDB, artefacts, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        changes: StateChangeSequence = []
        service_pattern = pattern[0]
        file_pattern = pattern.get('path')
        file_pattern[-1].alias = 'file'
        match_pattern = service_pattern.combine(file_pattern)
        file = file_pattern[-1].copy()
        file.alias = 'file'
        file.set('artefact_id', output.artefacts.get("downloaded_file_id"))
        changes.append((match_pattern, 'update', file))
        return changes