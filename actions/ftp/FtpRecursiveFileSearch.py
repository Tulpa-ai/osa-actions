import os
import re
from typing import Union
from ftplib import FTP, error_perm
from fuzzywuzzy import fuzz
from action_state_interface.action import Action, StateChangeSequence
from kg_api import Entity, Pattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif

FILES_AND_DIRS_TO_IGNORE = ['.', '..']

def sanitize_alias(name: str) -> str:
    """
    Sanitize a name to be used as a Cypher identifier alias.
    Replaces invalid characters (dots, hyphens, spaces, etc.) with underscores.
    """
    return re.sub(r'[^a-zA-Z0-9_]', '_', name)

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
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for FtpRecursiveFileSearch.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_FtpRecursiveFileSearch",
            description="Input motif for FtpRecursiveFileSearch"
        )
        input_motif.add_template(
            template_name="existing_asset",
            entity=Entity('Asset', alias='asset'),
        )
        input_motif.add_template(
            template_name="existing_port",
            entity=Entity('OpenPort', alias='port'),
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )
        input_motif.add_template(
            template_name="existing_service",
            entity=Entity('Service', alias='service', protocol='ftp'),
            relationship_type="is_running",
            match_on="existing_port",
            invert_relationship=True,
        )
        input_motif.add_template(
            template_name="existing_session",
            entity=Entity('Session', alias='session', protocol='ftp'),
            relationship_type="executes_on",
            match_on="existing_service",
        )
        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for FtpRecursiveFileSearch.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_FtpRecursiveFileSearch",
            description="Output motif for FtpRecursiveFileSearch"
        )

        output_motif.add_template(
            template_name="discovered_drive",
            entity=Entity('Drive', alias='drive'),
            relationship_type="accesses",
            match_on=Entity('Service', alias='service', protocol='ftp'),
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
        Expected outcome for FtpRecursiveFileSearch.
        """
        ip = pattern.get('asset').get('ip_address')
        service = pattern.get('service')._id
        return [f"Search for interesting files on FTP service ({service}) on {ip}"]

    def get_target_query(self) -> Query:
        query = self.input_motif.get_query()
        negate_pattern = self.input_motif.get_template('existing_service').entity.directed_path_to(Entity('File'))
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

    def parse_output(self, output: str) -> dict:
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
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        drive_change = self.output_motif.instantiate(
            template_name="discovered_drive",
            match_on_override=pattern.get('service'),
            location=f"FTP://{pattern.get('asset').get('ip_address')}/"
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
                    dirname=dirname,
                )
                if full_alias not in all_aliases:
                    all_aliases.add(full_alias)
                    changes.append(directory_change)

                current_directory_pattern = directory_change[2][-1]
            
            file_change = self.output_motif.instantiate(
                template_name="discovered_file",
                match_on_override=current_directory_pattern,
                filename=file_dict['filename'],
            )
            changes.append(file_change)
        return changes

    def capture_state_change(
        self, artefacts, pattern: Pattern, output
    ) -> StateChangeSequence:
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
