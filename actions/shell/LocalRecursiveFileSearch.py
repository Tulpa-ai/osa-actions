from typing import Any, Union

import paramiko

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import run_command
from builtin_actions.ftp.FtpRecursiveFileSearch import filter_files_by_wordlist  # isort:skip
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from kg_api.query import Query
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
            "LocalRecursiveFileSearch", "T1083", "TA0007", ["loud", "slow"]
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

    def get_target_query(self) -> Query:
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
        query = Query()
        query.match(match_pattern)
        query.where(credentials.username == session.username)
        query.ret_all()
        return query

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
        ssh_session = sessions.get_session(session_id).get_session_object()
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
