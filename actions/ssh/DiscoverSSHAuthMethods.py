import re
from typing import Any, Union

import paramiko

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import run_command, shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from kg_api.utils import safe_add_user
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
        super().__init__("DiscoverSSHAuthMethods", "T1078", "TA0001", ["quiet", "fast"])
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

    def get_target_query(self) -> Query:
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
        query = Query()
        query.match(pattern)
        query.where(other_service.protocol != "ssh")
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
        asset = pattern.get('asset')
        if 'noneauth' in clean:
            user.set('ssh_authentication', False)
        else:
            user.set('ssh_authentication', True)

        changes: StateChangeSequence = [
            (pattern, "update", user),
            (pattern, "merge_if_not_match", ssh_service - Relationship('is_client', direction='l') - user)
        ]

        return changes
