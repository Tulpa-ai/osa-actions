import os
from typing import Any, Union
from action_state_interface.action import Action, StateChangeSequence
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Ent, Entity, GraphDB, MultiPattern, Pattern, Rel, Relationship
from kg_api.query import Query
from kg_api.utils import safe_add_user

def get_ssh_user_accounts(path_list) -> list[str]:
    ssh_users = set()
    for path in path_list:
        parts = path.split(os.sep)
        if '.ssh' in parts:
            index = parts.index('.ssh')
            if index > 0:
                ssh_users.add(parts[index - 1])
    return list(ssh_users)

class FtpDiscoverSSHUserAccounts(Action):
    def __init__(self):
        super().__init__(
            "FtpDiscoverSSHUserAccounts", "T1083", "TA0007", ["quiet", "fast"]
        )
        self.noise = 0.2
        self.impact = 0.2

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        ip = pattern.get('asset').get('ip_address')
        service = pattern.get('service')._id
        return [f"Use the file system using the ftp service ({service}) on {ip} to infer SSH user accounts"]

    def get_target_query(self) -> Query:
        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service', protocol='ftp')
        match_pattern = (
            asset.with_edge(Relationship('has'))
            .with_node(Entity('OpenPort', alias='openport'))
            .with_edge(Relationship('is_running'))
            .with_node(service)
            .points_to(Entity('Drive'))
            .directed_path_to(Entity('Directory', dirname='.ssh'))
        )
        query = Query()
        query.match(match_pattern)
        query.ret_all()
        return query

    def function(self, sessions, artefacts, pattern: Pattern) -> str:
        ip = pattern.get('asset').get('ip_address')
        uuid = artefacts.search(f'FTP-directories-on-{ip}')[0]
        with artefacts.open(uuid, "rb") as f:
            all_files = [line.decode("utf-8").rstrip('\n') for line in f.readlines()]
        return all_files

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: Any
    ) -> StateChangeSequence:
        """Capture and update the knowledge graph based on discovered SSH user accounts.

        This function processes the output from the FTP discovery, extracts SSH user accounts,
        and updates the knowledge graph by linking users to the SSH service running on the asset.

        Args:
            kg (GraphDB): The knowledge graph database storing entity relationships.
            artefacts (ArtefactManager): Manages stored artefacts.
            pattern (Pattern): Contains asset-related information.
            output (list[str]): The list of discovered file paths.

        Returns:
            StateChangeSequence: A sequence of state changes to be applied to the knowledge graph.
        """
        changes: StateChangeSequence = []

        ssh_users = get_ssh_user_accounts(output)

        asset = pattern.get('asset')
        ssh_service = Ent('Service', alias='ssh_service', protocol='ssh')
        is_running = Rel('is_running')
        asset_port = asset - Rel('has') - Ent('OpenPort')
        asset_ssh_pattern = asset_port - is_running - ssh_service

        if len(ssh_users) > 0:
            changes.append((asset, 'merge_if_not_match', asset_ssh_pattern))

        for index, user in enumerate(ssh_users):
            user = Ent('User', alias=f'user{index}', username=user)
            changes.extend(safe_add_user(asset, ssh_service, user))
            
        return changes
