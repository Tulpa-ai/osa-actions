from typing import Union

import paramiko

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager


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
        super().__init__("SshLoginCredentials", "T1078", "TA0001", ["quiet", "fast"])
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

    def get_target_query(self) -> Query:
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
        query = Query()
        query.match(pattern)
        query.where(user.username == credentials.username)
        query.where(credentials.password.is_not_null())
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
