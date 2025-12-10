import re
from typing import Any, Union

import paramiko

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import run_command, shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, MultiPattern, Pattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation


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
        super().__init__("DiscoverSSHAuthMethods", "T1078", "TA0001", ["quiet", "fast"])
        self.noise = 0.2
        self.impact = 0.1
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for DiscoverSSHAuthMethods.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_DiscoverSSHAuthMethods",
            description="Input motif for DiscoverSSHAuthMethods"
        )
        input_motif.add_template(
            entity=Entity('Asset', alias='asset'),
            template_name="existing_asset",
        )
        input_motif.add_template(
            entity=Entity('OpenPort', alias='openport'),
            template_name="existing_port",
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )
        input_motif.add_template(
            entity=Entity('Service', alias='ssh_service', protocol='ssh'),
            template_name="existing_ssh_service",
            relationship_type="is_running",
            match_on="existing_port",
            invert_relationship=True,
        )
        input_motif.add_template(
            entity=Entity('Service', alias='other_service'),
            template_name="existing_other_service",
            relationship_type="directed_path",
            match_on="existing_asset",
        )
        input_motif.add_template(
            entity=Entity('User', alias='user'),
            template_name="existing_user",
            relationship_type="is_client",
            match_on="existing_other_service"
        )
        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for DiscoverSSHAuthMethods.
        
        The output motif creates:
        1. An updated User entity with ssh_authentication property
        2. A link from the updated User to the existing SSH Service via is_client relationship
        
        The updated_ssh_service template uses a placeholder match_on that will be overridden
        during instantiation to point to the existing SSH service from the input pattern.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_DiscoverSSHAuthMethods",
            description="Output motif for DiscoverSSHAuthMethods"
        )
        output_motif.add_template(
            entity=Entity('User', alias='user'),
            template_name="updated_user",
            operation=StateChangeOperation.UPDATE,
            expected_attributes=["ssh_authentication"],
        )
        output_motif.add_template(
            entity=Entity('Service', alias='ssh_service', protocol='ssh'),
            template_name="updated_ssh_service",
            relationship_type="is_client",
            match_on=Entity('User'),
            invert_relationship=True,
            operation=StateChangeOperation.MERGE_IF_NOT_MATCH,
        )
        return output_motif

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

    def get_target_query(self) -> Query:
        """
        get_target_patterns check looking for assets with an SSH service, and user accounts
        which are clients of another service on the same asset.
        """
        query = self.input_motif.get_query()
        query.where(self.input_motif.get_template('existing_other_service').entity.protocol != "ssh")
        query.ret_all()
        return query

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

    def parse_output(self, output: ActionExecutionResult, artefacts: ArtefactManager) -> dict:
        """
        Parse the output of the DiscoverSSHAuthMethods action.
        """
        lines = output.stdout.splitlines()
        auth_method_lines = [i for i, s in enumerate(lines) if s.startswith('|')]
        clean = []
        for line_idx in auth_method_lines:
            clean.extend(re.sub(r'[^a-zA-Z0-9 ]', '', lines[line_idx]).lstrip().lower().split())
        
        if 'noneauth' in clean:
            ssh_authentication = False
        else:
            ssh_authentication = True

        return {
            "ssh_authentication": ssh_authentication
        }

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate the output motif for DiscoverSSHAuthMethods.
        
        This method:
        1. Updates the user entity with ssh_authentication property
        2. Links the updated user to the existing SSH service via is_client relationship
        
        The updated_ssh_service template is instantiated with match_on_override pointing
        to the updated_user, creating the relationship: updated_user -[is_client]-> ssh_service.
        The MERGE_IF_NOT_MATCH operation ensures it matches the existing SSH service
        from the input pattern rather than creating a new one.
        
        For MERGE_IF_NOT_MATCH operations, the full pattern must be used as the first
        element of the tuple to properly match existing entities in the knowledge graph.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        user_from_pattern = pattern.get('user')
        ssh_service_from_pattern = pattern.get('ssh_service')

        changes.append(self.output_motif.instantiate(
            template_name="updated_user",
            match_on_override=user_from_pattern,
            ssh_authentication=discovered_data["ssh_authentication"],
        ))
        
        changes.append(self.output_motif.instantiate(
            template_name="updated_ssh_service",
            match_on_override=user_from_pattern,
            full_pattern_override=pattern,
            **ssh_service_from_pattern.kwargs
        ))
        
        return changes


    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: MultiPattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        If the user is configured with anonymous SSH login permissions.
        """
        discovered_data = self.parse_output(output, artefacts)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
