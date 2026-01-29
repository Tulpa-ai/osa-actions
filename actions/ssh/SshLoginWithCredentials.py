from typing import Union

import paramiko

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif


def get_ssh_terminal(ip: str, username: str, key_filename: str = None, password: str = None):
    """
    Use SSH credentials to establish an SSH session.
    """
    # Initialize the SSH client
    client = paramiko.SSHClient()
    # pkey = paramiko.RSAKey.from_private_key_file(key_filename)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the remote server
    try:
        client.connect(ip, username=username, key_filename=key_filename, password=password, look_for_keys=False)
        # Start an interactive shell session
        ssh_session = client.invoke_shell()
        return ssh_session
    except paramiko.ssh_exception.NoValidConnectionsError:
        return None


class SshLoginWithCredentials(Action):
    """
    Use SSH credentials to establish an SSH session.
    """

    def __init__(self):
        super().__init__("SshLoginWithCredentials", "T1078", "TA0001", ["quiet", "fast"])
        self.noise = 0.1
        self.impact = 0.5
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for SshLoginWithCredentials.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_SshLoginWithCredentials", description="Input motif for SshLoginWithCredentials"
        )

        input_motif.add_template(
            entity=Entity("Asset", alias="asset"),
            template_name="existing_asset",
        )

        input_motif.add_template(
            entity=Entity("OpenPort", alias="port"),
            template_name="existing_port",
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity("Service", alias="service", protocol="ssh"),
            template_name="existing_service",
            relationship_type="is_running",
            match_on="existing_port",
            invert_relationship=True,
        )

        # Credentials from any service on the same asset (can be reused from FTP, database, etc.)
        input_motif.add_template(
            entity=Entity('OpenPort', alias='cred_port'),
            template_name="existing_cred_port",
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity('Service', alias='cred_service'),
            template_name="existing_cred_service",
            relationship_type="is_running",
            match_on="existing_cred_port",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity("Credentials", alias="credentials"),
            template_name="existing_credentials",
            relationship_type="secured_with",
            match_on="existing_cred_service",
            expected_attributes=["password"],
        )

        input_motif.add_template(
            entity=Entity("User", alias="user"),
            template_name="existing_user",
            relationship_type="is_client",
            match_on="existing_cred_service",
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for SshLoginWithCredentials.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_SshLoginWithCredentials",
            description="Output motif for SshLoginWithCredentials"
        )

        output_motif.add_template(
            template_name="discovered_session",
            entity=Entity("Session", alias="session", protocol="ssh", active=True),
            relationship_type="executes_on",
            match_on=Entity("Service", alias="service", protocol="ssh"),
            expected_attributes=["id", "username", "password"]
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        ip = pattern.get('asset').get('ip_address')
        user = pattern.get('user').get('username')
        user_id = pattern.get('user')._id
        service = pattern.get('service')._id
        credentials = pattern.get('credentials')._id
        cred_service = pattern.get('cred_service')
        cred_service_protocol = cred_service.get('protocol') if cred_service else 'unknown'
        return [
            f"Gain access to {ip} as {user} ({user_id}) using credentials ({credentials}) from {cred_service_protocol} service via SSH service ({service})"
        ]

    def get_target_query(self) -> Query:
        """
        Get target patterns for SSH login with credentials from any service.
        Works with credentials from any service (FTP, MySQL, SSH itself, etc.).
        """
        query = self.input_motif.get_query()
        query.where(
            self.input_motif.get_template('existing_user').entity.username ==
            self.input_motif.get_template('existing_credentials').entity.username
        )
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Extract credentials from the target pattern and use them to
        establish an SSH session.
        """
        asset = pattern.get('asset')
        ip_address = asset.get('ip_address')
        user = pattern.get('user')
        username = user.get('username')
        credentials = pattern.get('credentials')
        username = credentials.get('username')
        password = credentials.get('password')
        channel = get_ssh_terminal(ip_address, username, password=password)
        # Capture the output
        output = ""
        while channel.recv_ready():  # Keep receiving while data is available
            output += channel.recv(1024).decode()

        print("SSH session output:\n", output)

        sess_id = sessions.add_session(channel)
        return ActionExecutionResult(
            command=["sshpass", "-p", password, "ssh", f"{username}@{ip_address}"],
            stdout=output,
            session=sess_id,
            logs=[f"Established session ID {sess_id} on {ip_address} with {username} and password: {password}"],
        )

    def parse_output(self, output: ActionExecutionResult) -> dict:
        """
        Parse the output of the SshLoginWithCredentials action.
        """
        return {
            "discovered_session": output.session,
        }

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate the output motif for SshLoginWithCredentials.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        user = pattern.get('user')
        username = user.get('username')
        credentials = pattern.get('credentials')
        password = credentials.get('password')
        service = pattern.get('service')

        session_change = self.output_motif.instantiate(
            template_name="discovered_session",
            match_on_override=service,
            id=discovered_data["discovered_session"],
            username=username,
            password=password,
            active=True,
        )
        changes.append(session_change)
        return changes


    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Update knowledge graph with newly established session.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
