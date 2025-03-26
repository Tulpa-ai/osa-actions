import os
from typing import Union
from action_state_interface.action import Action, StateChangeSequence
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship

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
            "FtpDiscoverSSHUserAccounts", "T1083 File and Directory Discovery", "TA0007 Discovery", ["quiet", "fast"]
        )
        self.noise = 0.2
        self.impact = 0.2

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        ip = pattern.get('asset').get('ip_address')
        service = pattern.get('service')._id
        return [f"Use the file system using the ftp service ({service}) on {ip} to infer SSH user accounts"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
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
        res = kg.get_matching(match_pattern)
        return res

    def function(self, sessions, artefacts, pattern: Pattern) -> str:
        ip = pattern.get('asset').get('ip_address')
        uuid = artefacts.search(f'FTP-directories-on-{ip}')[0]
        with artefacts.open(uuid, "rb") as f:
            all_files = [line.decode("utf-8").rstrip('\n') for line in f.readlines()]
        return all_files

    def capture_state_change(
        self, kg: GraphDB, artefacts, pattern: Pattern, output
    ) -> StateChangeSequence:
        changes: StateChangeSequence = []
        ssh_users = get_ssh_user_accounts(output)
        asset = pattern.get('asset')
        ftp_service = Entity('Service', alias='ftp_service', protocol='ftp')
        ssh_service = Entity('Service', alias='ssh_service', protocol='ssh')
        is_running = Relationship('is_running', direction='r')
        asset_port = asset.with_edge(Relationship('has', direction='r')).with_node(Entity('OpenPort'))
        asset_ftp_pattern = asset_port.with_edge(is_running).with_node(ftp_service)
        asset_ssh_pattern = asset_port.with_edge(is_running).with_node(ssh_service)
        if len(ssh_users) > 0:
            changes.append((asset, 'merge_if_not_match', asset_ssh_pattern))
        for index, user in enumerate(ssh_users):
            user_entity = Entity('User', alias=f'user{index}', username=user)
            user_ftp_pattern = ftp_service.with_edge(Relationship('is_client', direction='l')).with_node(user_entity)
            changes.append((asset_ftp_pattern, 'merge_if_not_match', user_ftp_pattern))
            user_pattern = asset_ftp_pattern.with_edge(Relationship('is_client', direction='l')).with_node(user_entity)
            user_ssh_pattern = ssh_service.with_edge(Relationship('is_client', direction='l')).with_node(user_entity)
            combined = asset_ssh_pattern.combine(user_pattern)
            changes.append((combined, 'merge_if_not_match', user_ssh_pattern))
        return changes