import os
from pathlib import Path
from ftplib import FTP, error_perm
from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionError, ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation

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
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for FtpDownloadFile.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_FtpDownloadFile",
            description="Input motif for FtpDownloadFile"
        )

        input_motif.add_template(
            template_name="existing_asset",
            entity=Entity('Asset', alias='asset'),
        )

        input_motif.add_template(
            template_name="existing_port",
            entity=Entity('OpenPort', alias='port'),
            match_on="existing_asset",
            relationship_type="has",
            invert_relationship=True,
        )

        input_motif.add_template(
            template_name="existing_service",
            entity=Entity('Service', alias='service', protocol='ftp'),
            match_on="existing_port",
            relationship_type="is_running",
            invert_relationship=True,
        )

        input_motif.add_template(
            template_name="existing_drive",
            entity=Entity('Drive', alias='drive'),
            match_on="existing_service",
            relationship_type="accesses",
            invert_relationship=True,
        )

        input_motif.add_template(
            template_name="existing_file",
            entity=Entity('File', alias='file', filename='id_rsa'),
            match_on="existing_drive",
            relationship_type="directed_path",
            pattern_alias='path_to_file',
        )

        input_motif.add_template(
            template_name="existing_session",
            entity=Entity('Session', alias='session', protocol='ftp'),
            match_on="existing_service",
            relationship_type="executes_on"
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for FtpDownloadFile.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_FtpDownloadFile",
            description="Output motif for FtpDownloadFile"
        )
        output_motif.add_template(
            template_name="downloaded_file",
            entity=Entity('File', alias='file', filename='id_rsa'),
            expected_attributes=["artefact_id"],
            operation=StateChangeOperation.UPDATE
        )
        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        filename = pattern.get('path_to_file')[-1].get('filename')
        ip = pattern.get('asset').get('ip_address')
        session = pattern.get('session')._id
        service = pattern.get('service')._id
        return [f"Download file {filename} from FTP service ({service}) on {ip} using session ({session})"]

    def get_target_query(self) -> Query:
        query = self.input_motif.get_query()
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts, pattern: Pattern) -> ActionExecutionResult:
        session = pattern.get('session')
        session_id = session.get('id')
        ftp_connection_details: dict = sessions.get_session(session_id)
        hostname = ftp_connection_details["host"]
        username = ftp_connection_details["username"]
        password = ftp_connection_details["password"]
        path_pattern: Pattern = pattern.get('path_to_file')
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

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate the output motif for FtpDownloadFile.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        file_from_pattern = pattern.get('path_to_file')[-1]
        file_from_pattern.alias = 'file'
        changes.append(
            self.output_motif.instantiate(
                template_name="downloaded_file",
                match_on_override=file_from_pattern,
                artefact_id=discovered_data["downloaded_file_id"]
            )
        )
        return changes


    def parse_output(self, output: ActionExecutionResult, artefacts: ArtefactManager) -> dict:
        """
        Parse the output of the FtpDownloadFile.
        """
        return {
            "downloaded_file_id": output.artefacts.get("downloaded_file_id")
        }

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        discovered_data = self.parse_output(output, artefacts)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes