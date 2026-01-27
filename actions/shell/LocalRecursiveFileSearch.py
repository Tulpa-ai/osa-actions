from typing import Any, Union

import paramiko
import re

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import run_command
from builtin_actions.ftp.FtpRecursiveFileSearch import filter_files_by_wordlist  # isort:skip
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif


def sanitize_alias(name: str) -> str:
    """
    Sanitize a name to be used as a Cypher identifier alias.
    Replaces invalid characters (dots, hyphens, spaces, etc.) with underscores.
    """
    return re.sub(r'[^a-zA-Z0-9_]', '_', name)

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
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for LocalRecursiveFileSearch.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_LocalRecursiveFileSearch",
            description="Input motif for LocalRecursiveFileSearch"
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
            entity=Entity('Credentials', alias='credentials'),
            template_name="existing_credentials",
            relationship_type="secured_with",
            match_on="existing_service",
        )

        input_motif.add_template(
            entity=Entity('Session', alias='session', protocol='ssh', active=True),
            template_name="existing_session",
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for LocalRecursiveFileSearch.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_LocalRecursiveFileSearch",
            description="Output motif for LocalRecursiveFileSearch"
        )

        output_motif.add_template(
            template_name="discovered_drive",
            entity=Entity('Drive', alias='drive'),
            relationship_type="accesses",
            match_on=Entity('Asset', alias='asset'),
            invert_relationship=True,
            expected_attributes=["location"],
        )

        output_motif.add_template(
            template_name="discovered_directory",
            entity=Entity('Directory', alias='directory'),
            relationship_type="has",
            match_on="discovered_drive",
            invert_relationship=True,
        )

        output_motif.add_template(
            template_name="discovered_file",
            entity=Entity('File', alias='file'),
            relationship_type="has",
            match_on="discovered_directory",
            invert_relationship=True,
        )

        return output_motif

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
        query = self.input_motif.get_query()
        query.where(self.input_motif.get_template('existing_credentials').entity.username == self.input_motif.get_template('existing_session').entity.username)
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

    def parse_output(self, output: Any) -> dict:
        """
        Parse the output of the action.
        """
        if len(output) == 0:
            return {}

        discovered_files = []
        for filename in output:
            path_list = [f for f in filename.split('/') if len(f) > 0]
            filename = path_list.pop()
            
            directory_list = []
            for index, path in enumerate(path_list):
                directory_list.append({
                    'dirname': path,
                    'index': index
                })

            discovered_files.append({
                'filename': filename,
                'path': path_list,
                'directory_list': directory_list,
            })
        return discovered_files
                

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate the output motif with the discovered data.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        drive_change = self.output_motif.instantiate(
            template_name="discovered_drive",
            match_on_override=pattern.get('asset'),
            location=f"{pattern.get('asset').get('ip_address')}/"
        )
        changes.append(drive_change)
        drive_pattern = drive_change[2][-1]
        all_aliases = set()

        for file_dict in discovered_data:
            full_alias = 'drive'
            all_aliases.add(full_alias)
            current_directory_pattern = drive_pattern
            for directory_dict in file_dict['directory_list']:
                dirname = directory_dict['dirname']
                sanitized_dirname = sanitize_alias(dirname)
                full_alias += f'_{sanitized_dirname}'

                directory_change = self.output_motif.instantiate(
                    template_name="discovered_directory",
                    alias=full_alias,
                    match_on_override=current_directory_pattern,
                    dirname=dirname
                )
                if full_alias not in all_aliases:
                    all_aliases.add(full_alias)
                    changes.append(directory_change)

                current_directory_pattern = directory_change[2][-1]

            file_change = self.output_motif.instantiate(
                template_name="discovered_file",
                match_on_override=current_directory_pattern,
                filename=file_dict['filename'],
                active=True,
            )
            changes.append(file_change)
        
        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: Any
    ) -> StateChangeSequence:
        """
        Update the knowledge graph with discovered files.

        If interesting files are found, they are added to the knowledge graph, associating them with
        the asset and its directory structure.

        Args:
            artefacts (ArtefactManager): Manages stored artefacts.
            pattern (Pattern): The pattern containing asset details.
            output (Any): The list of discovered files.

        Returns:
            StateChangeSequence: A sequence of state changes to be applied to the knowledge graph.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes