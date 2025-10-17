import os
from typing import Union
from ftplib import FTP, error_perm
from fuzzywuzzy import fuzz
from action_state_interface.action import Action, StateChangeSequence
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager

FILES_AND_DIRS_TO_IGNORE = ['.', '..']

def list_files_recursive(ftp, path='/', depth=1, max_depth=2, file_list=None) -> list[str]:
    # ...existing code...
    if file_list is None:
        file_list = []
    if depth > max_depth:
        return file_list
    try:
        ftp.cwd(path)
    except error_perm:
        return file_list
    items = []
    try:
        ftp.retrlines('LIST -a', items.append)
    except error_perm:
        ftp.retrlines('LIST', items.append)
    for item in items:
        parts = item.split()
        name = parts[-1]
        if name in FILES_AND_DIRS_TO_IGNORE:
            continue
        item_type = item[0]
        if item_type == 'd':
            list_files_recursive(ftp, path=f"{path}{name}/", depth=depth+1, max_depth=max_depth, file_list=file_list)
        elif item_type == "l":
            continue
        else:
            full_path = f"{path}{name}"
            file_list.append(full_path)
    ftp.cwd('..')
    return file_list

def filter_files_by_wordlist(file_list: list[str], wordlist: list[str], similarity_thresh: float = 80) -> list[str]:
    # ...existing code...
    base_names_dict = {os.path.basename(file): file for file in file_list}
    all_files = list(set(file_list + list(base_names_dict.keys())))
    out = []
    for file in all_files:
        for word in wordlist:
            if fuzz.ratio(file, word) >= similarity_thresh:
                out.append(base_names_dict.get(file, file))
    return out

class FtpRecursiveFileSearch(Action):
    def __init__(self):
        super().__init__(
            "FtpRecursiveFileSearch", "T1083", "TA0007", ["quiet", "fast"]
        )
        self.noise = 0.2
        self.impact = 0.8

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        ip = pattern.get('asset').get('ip_address')
        service = pattern.get('service')._id
        return [f"Search for interesting files on FTP service ({service}) on {ip}"]

    def get_target_query(self) -> Query:
        session = Entity('Session', alias='session', protocol='ftp')
        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service', protocol='ftp')
        match_pattern = (
            asset.with_edge(Relationship('has'))
            .with_node(Entity('OpenPort', alias='openport'))
            .with_edge(Relationship('is_running'))
            .with_node(service)
            .combine(session)
        )
        negate_pattern = service.directed_path_to(Entity('File'))
        query = Query()
        query.match(match_pattern)
        query.where(service.id() == session.executes_on)
        query.where(negate_pattern, _not=True)
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts, pattern: Pattern) -> str:
        uuid = artefacts.search('interesting_file_names.txt')[0]
        with artefacts.open(uuid, "r") as f:
            wordlist = {line.strip() for line in f}
        wordlist.discard('')
        session = pattern.get('session')
        session_id = session.get('id')
        ftp_connection_details: dict = sessions.get_session(session_id)
        hostname = ftp_connection_details["host"]
        username = ftp_connection_details["username"]
        password = ftp_connection_details["password"]
        with FTP(host=hostname, user=username, passwd=password) as ftp_session:
            all_files = list_files_recursive(ftp_session, path='/', max_depth=3)
        interesting_files = filter_files_by_wordlist(all_files, wordlist)
        ip = pattern.get('asset').get('ip_address')
        uuid = artefacts.placeholder(f'FTP-directories-on-{ip}')
        with artefacts.open(uuid, "wb") as f:
            for file in all_files:
                f.write(file.encode("utf-8") + b'\n')
        return interesting_files

    def capture_state_change(
        self, kg: GraphDB, artefacts, pattern: Pattern, output
    ) -> StateChangeSequence:
        changes: StateChangeSequence = []
        if len(output) == 0:
            return changes
        asset = pattern.get('asset')
        ftp_service = pattern.get('service')
        ip_address = asset.get('ip_address')
        ftp_match_pattern = (
            asset.with_edge(Relationship('has'))
            .with_node(Entity('OpenPort'))
            .with_edge(Relationship('is_running'))
            .with_node(ftp_service)
        )
        drive = Entity('Drive', alias='drive', location=f'FTP://{ip_address}/')
        service_drive_pattern = ftp_service.with_edge(Relationship('accesses', direction='r')).with_node(drive)
        changes.append((ftp_match_pattern, 'merge_if_not_match', service_drive_pattern))
        ftp_drive_pattern = ftp_match_pattern.with_edge(Relationship('accesses', direction='r')).with_node(drive)
        for filename in output:
            path_list = [f for f in filename.split('/') if len(f) > 0]
            filename = path_list.pop()
            match_pattern = ftp_drive_pattern
            merge_pattern = drive
            for index, path in enumerate(path_list):
                directory = Entity('Directory', alias=f'directory{index}', dirname=path)
                merge_pattern = merge_pattern.with_edge(Relationship('has', direction='r')).with_node(directory)
                changes.append((match_pattern, "merge_if_not_match", merge_pattern))
                match_pattern = match_pattern.with_edge(Relationship('has', direction='r')).with_node(directory)
                merge_pattern = directory
            merge_pattern = merge_pattern.with_edge(Relationship('has', direction='r')).with_node(
                Entity(type='File', filename=filename)
            )
            changes.append((match_pattern, "merge_if_not_match", merge_pattern))
        return changes