import re
from pathlib import Path
from typing import Any, Union

import paramiko
import sh

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import run_command, shell
from action_state_interface.exec import ActionExecutionError, ActionExecutionResult
from action_state_interface.actions.ftp_actions import filter_files_by_wordlist
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from Session import SessionManager


def list_files(ssh_client: paramiko.SSHClient, start_path: str = "/"):
    """Recursively searches for files on a remote system via an SSH session.

    :param ssh_client: Active paramiko SSHClient instance
    :param start_path: Directory to start the search from (default is root)
    :return: List of file paths
    """
    try:
        command = f'find "{start_path}" -type f 2>/dev/null'
        file_paths = run_command(ssh_client, command)
        return [fp.strip() for fp in file_paths]
    except Exception as e:
        print(f"Error occurred: {e}")
        return []


class DiscoverSSHAuthMethods(Action):
    """
    Use NMAP to discover anonymous login permissions to an SSH account.
    This action is performed against (Asset, Port, User) patterns.
    """

    def __init__(self):
        super().__init__("DiscoverSSHAuthMethods", "T1078 Valid Accounts", "TA0001 Initial Access", ["quiet", "fast"])
        self.noise = 0.2
        self.impact = 0.1

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        user = pattern.get('user').get('username')
        user_id = pattern.get('user')._id
        ip = pattern.get('asset').get('ip_address')
        port_num = pattern.get('openport').get('number')
        ssh_service = pattern.get('ssh_service')._id
        return [
            f"Gain SSH access to {user} ({user_id}) on {ip} via port with number {port_num}, using SSH service ({ssh_service})"
        ]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check looking for assets with an SSH service, and user accounts
        which are clients of another service on the same asset.
        """
        asset = Entity('Asset', alias='asset')
        openport = Entity('OpenPort', alias='openport')
        ssh_service = Entity('Service', alias='ssh_service', protocol='ssh')
        other_service = Entity('Service', alias='other_service')
        user = Entity('User', alias='user')
        pattern = (
            asset.points_to(openport)
            .points_to(ssh_service)
            .combine(
                asset.directed_path_to(other_service)
                .with_edge(Relationship('is_client', direction='l'))
                .with_node(user)
            )
        )
        return kg.match(pattern).where("other_service.protocol <> 'ssh'")

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use execute function from action_utils to execute NMAP command.
        """
        ip = pattern.get('asset').get('ip_address')
        portnum = pattern.get('openport').get('number')
        username = pattern.get('user').get('username')
        res = shell(
            "nmap", ["--script=ssh-auth-methods", f"--script-args='ssh.user={username}'", "-p", str(portnum), ip]
        )
        return res

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: MultiPattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        If the user is configured with anonymous SSH login permissions.
        """
        lines = output.stdout.splitlines()
        auth_method_lines = [i for i, s in enumerate(lines) if s.startswith('|')]
        clean = []
        for line_idx in auth_method_lines:
            clean.extend(re.sub(r'[^a-zA-Z0-9 ]', '', lines[line_idx]).lstrip().lower().split())
        ssh_pattern = pattern._patterns[0]
        ssh_service = ssh_pattern.get('ssh_service')
        user = pattern.get('user')
        if 'noneauth' in clean:
            user.set('ssh_authentication', False)
        else:
            user.set('ssh_authentication', True)
        merge_pattern = ssh_service.with_edge(Relationship('is_client', direction='l')).with_node(user)

        changes: StateChangeSequence = [(pattern, "update", user), (ssh_pattern, "merge", merge_pattern)]
        return changes


class LocalRecursiveFileSearch(Action):
    """Implements a function to list files on an asset.

    This class defines an action to exhaustively search for files at varying depths within a file system.
    The search is conducted by using SSH access to an asset, identifying files of interest.
    """

    def __init__(self):
        """
        Initialize the LocalRecursiveFileSearch action with predefined attributes.

        - The action is associated with T1083 (File and Directory Discovery) under the MITRE ATT&CK framework.
        - The action belongs to the Discovery tactic (TA0007).
        - Supports optional parameters: "quiet" and "fast".
        """
        super().__init__(
            "LocalRecursiveFileSearch", "T1083 File and Directory Discovery", "TA0007 Discovery", ["loud", "slow"]
        )
        self.noise = 1
        self.impact = 0.3

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Define the expected outcome of the action.

        Args:
            pattern (Pattern): The pattern containing asset information.

        Returns:
            list[str]: A list containing a description of the search operation.
        """
        ip = pattern.get('asset').get('ip_address')
        creds = pattern.get('credentials')._id
        service = pattern.get('service')._id
        session = pattern.get('session')._id
        return [
            f"Search for interesting files on the file system of {ip} with discovered credentials ({creds}) via SSH service ({service}) using session ({session})"
        ]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        Identify target patterns where the search operation should be performed.

        This method looks for FTP Service entities on which the agent has an active session.

        Args:
            kg (GraphDB): The knowledge graph database to query for matching patterns.

        Returns:
            list[Union[Pattern, MultiPattern]]: A list of patterns representing target locations.
        """
        session = Entity('Session', alias='session', protocol='ssh')
        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service', protocol='ssh')
        credentials = Entity('Credentials', alias='credentials')
        match_pattern = (
            asset.directed_path_to(service)
            .with_edge(Relationship('secured_with', direction='l'))
            .with_node(credentials)
            .combine(session)
        )
        res = kg.match(match_pattern).where("credentials.username = session.username")
        return res

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> str:
        """
        Perform a recursive file search using an FTP session.

        Reads a list of interesting file names from an artefact and searches for matching files.

        Args:
            sessions (SessionManager): Manages active sessions.
            artefacts (ArtefactManager): Manages stored artefacts.
            pattern (Pattern): The pattern containing session and asset details.

        Returns:
            str: A list of interesting files found.
        """
        uuid = artefacts.search('interesting_file_names.txt')[0]
        with artefacts.open(uuid, "r") as f:
            wordlist = {line.strip() for line in f}
        wordlist.discard('')
        session: Entity = pattern.get('session')
        session_id = session.get('id')
        ssh_session = sessions.get_session(session_id)
        all_files = list_files(ssh_session)
        interesting_files = filter_files_by_wordlist(all_files, wordlist)
        ip = pattern.get('asset').get('ip_address')
        uuid = artefacts.placeholder(f'FTP-directories-on-{ip}')
        with artefacts.open(uuid, "wb") as f:
            for file in all_files:
                f.write(file.encode("utf-8") + b'\n')
        return interesting_files

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: Any
    ) -> StateChangeSequence:
        """
        Update the knowledge graph with discovered files.

        If interesting files are found, they are added to the knowledge graph, associating them with
        the asset and its directory structure.

        Args:
            kg (GraphDB): The knowledge graph to update.
            artefacts (ArtefactManager): Manages stored artefacts.
            pattern (Pattern): The pattern containing asset details.
            output (Any): The list of discovered files.

        Returns:
            StateChangeSequence: A sequence of state changes to be applied to the knowledge graph.
        """

        changes: StateChangeSequence = []

        if len(output) == 0:
            return changes

        asset: Entity = pattern.get('asset')
        ip_address = asset.get('ip_address')

        drive = Entity('Drive', alias='drive', location=f'{ip_address}/')
        asset_drive_pattern = asset.with_edge(Relationship('accesses', direction='r')).with_node(drive)
        changes.append((asset, 'merge_if_not_match', asset_drive_pattern))

        for filename in output:
            path_list = [f for f in filename.split('/') if len(f) > 0]
            filename = path_list.pop()

            match_pattern = asset_drive_pattern
            merge_pattern = drive

            n = 0
            for path in path_list:
                directory = Entity('Directory', alias=f'directory{n}', dirname=path)
                merge_pattern = merge_pattern.with_edge(Relationship('has', direction='r')).with_node(directory)
                changes.append((match_pattern, "merge_if_not_match", merge_pattern))
                match_pattern = match_pattern.with_edge(Relationship('has', direction='r')).with_node(directory)
                merge_pattern = directory
                n += 1

            merge_pattern = merge_pattern.with_edge(Relationship('has', direction='r')).with_node(
                Entity(type='File', filename=filename)
            )
            changes.append((match_pattern, "merge_if_not_match", merge_pattern))

        return changes


class ScpGetFile(Action):
    """
    Represents an action to retrieve a file from a remote system via SCP (Secure Copy Protocol)
    in the context of cybersecurity attack simulations.
    """

    def __init__(self):
        """
        Initializes the ScpGetFile action with a specific attack identifier,
        tactic, and technique information.
        """
        super().__init__("ScpGetFile", "T1083 File and Directory Discovery", "TA0007 Discovery", ["loud", "fast"])
        self.noise = 0.3
        self.impact = 1

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """Generates the expected outcome for the action based on the provided pattern.

        Args:
            pattern (Pattern): A pattern object containing asset and file information.

        Returns:
            list[str]: A list describing the expected result of retrieving the file.
        """
        ip = pattern.get('asset').get('ip_address')
        path_pattern: Pattern = pattern.get('filepath')
        filepath = Path('/')
        for g_obj in path_pattern:
            if g_obj.type == 'Directory':
                filepath = filepath / g_obj.get('dirname')
            if g_obj.type == 'File':
                filepath = filepath / g_obj.get('filename')
        return [f"Get {filepath} from {ip}"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        Identifies target patterns within the knowledge graph that match conditions for
        performing the SCP action.

        Args:
            kg (GraphDB): A knowledge graph object representing system entities and relationships.

        Returns:
            list[Union[Pattern, MultiPattern]]: A list of matching patterns representing valid targets.
        """
        asset = Entity('Asset', alias='asset')
        has = Relationship('has')
        port = Entity('OpenPort', alias='openport')
        is_running = Relationship('is_running')
        service = Entity('Service', alias='service', protocol='ssh')
        secured_with = Relationship('secured_with', direction='l')
        credentials = Entity('Credentials', alias='credentials')
        file = Entity(type='File', alias='file', filename='id_rsa')
        drive = Entity('Drive', alias='drive')
        file_pattern = drive.directed_path_to(file)
        file_pattern.set_alias('filepath')
        match_pattern = (
            asset.with_edge(has)
            .with_node(port)
            .with_edge(is_running)
            .with_node(service)
            .with_edge(secured_with)
            .with_node(credentials)
            .combine(asset.connects_to(drive))
            .combine(file_pattern)
        )
        return kg.get_matching(match_pattern)

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Executes the SCP command to retrieve a specified file from a remote system.

        Args:
            sessions (SessionManager): Manages SSH session connections.
            artefacts (ArtefactManager): Manages artefacts resulting from the SCP action.
            pattern (Pattern): A pattern object describing the target file and session details.

        Returns:
            str: The result of the SCP command execution.
        """
        ip = pattern.get('asset').get('ip_address')
        portnum = pattern.get('openport').get('number')
        username = pattern.get('credentials').get('username')
        path_pattern: Pattern = pattern.get('filepath')
        filepath = Path('/')
        for g_obj in path_pattern:
            if g_obj.type == 'Directory':
                filepath = filepath / g_obj.get('dirname')
            if g_obj.type == 'File':
                filepath = filepath / g_obj.get('filename')
        filename = path_pattern[-1].get('filename')
        uuid = artefacts.placeholder(filename)
        artefact_path = artefacts.get_path(uuid)

        command, argv = None, []
        if password := pattern.get('credentials').get('password'):
            command = "sshpass"
            argv = [
                "-p",
                f"{password}",
                "scp",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                f"{username}@{ip}:{filepath}",
                f"{artefact_path}",
            ]
        elif ssh_key_file := pattern.get('credentials').get('key_file'):
            command = "scp"
            argv = [
                "-P",
                f"{portnum}",
                "-i",
                f"{ssh_key_file}",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                f"{username}@{ip}:{filepath}",
                f"{artefact_path}",
            ]

        if command is not None:
            try:
                res = shell(command, argv)
            except sh.ErrorReturnCode:
                raise ActionExecutionError(
                    f"Error when trying to run {command} {argv} to download '{filepath}' from {ip}"
                )
            res.artefacts[filename] = uuid
            return res
        raise ActionExecutionError("ScpGetFile: cannot run action, unable to extract the necessary values")

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Captures the state change in the knowledge graph after the SCP action.

        Args:
            kg (GraphDB): The knowledge graph representing the current state of the system.
            artefacts (ArtefactManager): Manages artefacts related to the SCP action.
            pattern (Pattern): The pattern describing the targeted asset and file.
            output (ActionExecutionResult): The result of the SCP command execution.

        Returns:
            StateChangeSequence: A sequence of changes made to the system state.
        """

        changes: StateChangeSequence = []

        as_pattern = pattern[0]
        file_pattern = pattern.get('filepath')
        file_pattern[-1].alias = 'file'
        match_pattern = as_pattern.combine(file_pattern)
        file = file_pattern[-1].copy()
        file.alias = 'file'
        file.set('artefact_id', output.artefacts[file.get('filename')])

        changes.append((match_pattern, 'update', file))

        return changes


actions = [DiscoverSSHAuthMethods(), LocalRecursiveFileSearch()]
