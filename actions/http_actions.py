import random
import re
import uuid
from pathlib import Path
from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from Session import SessionManager


def cmd_discover_webapp_files_and_folders(
    url,
    wordlist="/usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt",
    output="../02-gobuster-dir-scan-output.txt",
    ignore="403,404",
) -> ActionExecutionResult:
    """
    Use gobuster command to discover files and folders on a web application.
    """
    res = shell(
        "gobuster", ["dir", "-u", url, "-w", wordlist, "-o", output, "-b", ignore, "--timeout", "20s", "--no-color"]
    )
    res.artefacts["json_report"] = output
    return res


def get_new_filestore_key(seed=24601):
    """
    Generate uuids to reference discovered files.
    """
    # NOTE: tmp fix - always returns the same UUID.
    random.seed(seed)
    return str(uuid.UUID(int=random.getrandbits(128), version=4))


def cmd_fetch_file_http(download_url, savepath):
    """
    Use curl to download a file from an HTTP server.
    """
    if not savepath.exists():
        shell(
            "curl",
            [
                "-v",
                "-s",
                "--output",
                savepath.as_posix(),
                download_url,
            ],
        )


def cmd_get_file_info(filepath) -> tuple[str, str]:
    """
    Get the mime info of a downloaded file.
    """
    fileinfo = shell("file", ["-b", "--mime", filepath.as_posix()])  # Keep the output brief

    mime_type, mime_encoding = [x.strip() for x in fileinfo.split(";")]
    return mime_type, mime_encoding


class HttpGobuster(Action):
    """
    Use gobuster command to scan HTTP service and list files and folders.
    """

    def __init__(self):
        super().__init__("HttpGobuster", "T1083 File and Directory Discovery", "TA0007 Discovery", ["quiet", "fast"])
        self.noise = 0.8
        self.impact = 0.4

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        ip = pattern.get('asset').get('ip_address')
        service = pattern.get('service')._id
        return [f"Gain knowledge to gain access to {ip} via HTTP service ({service})"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check looking for HTTP services, drives and directories.
        """
        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service', protocol='http')
        pattern = asset.directed_path_to(service)
        return kg.get_matching(pattern)

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Execute gobuster command on the ip associated with the HTTP service.
        Save output to a file.
        """
        ip = pattern.get('asset').get('ip_address')
        uuid = artefacts.placeholder('gobuster-dir-scan-output.txt')
        out_path = artefacts.get_path(uuid)
        gobuster_report = cmd_discover_webapp_files_and_folders(url=f"http://{ip}", output=out_path)
        return gobuster_report

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Updating knowledge graph with discovered files and folders.
        """
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        pss_pattern = re.compile(r'(?P<path>/\S+)\s+\(Status: (?P<status>\d{3})\) \[Size: (?P<size>\d+)\]')

        files_and_folders = []
        for line in output.stdout.splitlines():
            clean = ansi_escape.sub('', line)
            if match := re.match(pss_pattern, clean):
                files_and_folders.append(
                    {
                        'path': match.group('path'),
                        'status': int(match.group('status')),
                        'size': int(match.group('size')),
                    }
                )

        asset = pattern.get('asset')
        service = pattern.get('service')
        ip = asset.get('ip_address')

        drive = Entity('Drive', alias='drive', location=f'http://{ip}')
        sd_pattern = service.with_edge(Relationship('accesses', direction='r')).with_node(drive)

        changes: StateChangeSequence = []

        changes.append((pattern, 'merge_if_not_match', sd_pattern))

        asd_pattern = (
            asset.directed_path_to(service).with_edge(Relationship('accesses', direction='r')).with_node(drive)
        )

        for file in files_and_folders:
            path, status, size = file["path"], file["status"], file["size"]

            path_list = [dir for dir in path.split('/') if dir != '']

            directory = Entity('Directory', alias='directory', dirname=path_list[0], status=status, size=size)
            merge_pattern = drive.with_edge(Relationship('has', direction='r')).with_node(directory)
            changes.append((asd_pattern, "merge_if_not_match", merge_pattern))

        return changes


class HttpDownloadFile(Action):
    """
    Use curl to download files discovered on a HTTP service drive.
    """

    def __init__(self):
        super().__init__(
            "HttpDownloadFile", "T1567 Exfiltration Over Web Service", "TA0010 Exfiltration", ["quiet", "fast"]
        )
        self.noise = 0
        self.impact = 0.02

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        return [f"Gain knowledge to gain access to {pattern.get('asset').get('ip_address')}"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check to identify files and directories on a HTTP service
        drive.
        """
        asset = Entity('Asset', alias='asset')
        port = Entity('OpenPort', alias='port')
        service = Entity('Service', alias='service', protocol='http')
        drive = Entity('Drive', alias='drive')
        directory = Entity('Directory', alias='directory', dirname='database')
        file = Entity('File', alias='file')
        pattern = asset.points_to(port).points_to(service).points_to(drive).points_to(directory).points_to(file)
        return kg.get_matching(pattern)

    def function(self, sessions: SessionManager, pattern: Pattern) -> tuple[str, str]:
        """
        Use curl to download the target file.
        """
        port = pattern.get('port')
        drive = pattern.get('drive')
        directory = pattern.get('directory')
        file = pattern.get('file')
        download_url = f"{drive.get('location').lower()}:{port.get('number')}/{directory.get('dirname')}"
        save_path = Path('..') / Path(file.get('uuid'))
        cmd_fetch_file_http(download_url, save_path)
        mime_type, mime_encoding = cmd_get_file_info(save_path)
        return mime_type, mime_encoding

    def capture_state_change(self, kg: GraphDB, pattern: Pattern, output: tuple[str, str]) -> StateChangeSequence:
        """
        Update the knowledge graph to reflect the downloaded state of the target file.
        """
        file = pattern.get('file')
        mime_type, mime_encoding = output
        new_file = file.copy()
        new_file.set('mime_type', mime_type)
        new_file.set('mime_encoding', mime_encoding)
        new_file.set('downloaded', True)
        changes: StateChangeSequence = [(pattern, "update", new_file)]
        return changes


class HttpGetLoginPages(Action):
    """
    Use GoSpider to crawl a web app and identify any login forms.
    """

    def __init__(self):
        super().__init__(
            "HttpGetLoginPages", "T1083 File and Directory Discovery", "TA0007 Discovery", ["quiet", "fast"]
        )
        self.noise = 0.4
        self.impact = 0.2

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        ip = pattern.get('asset').get('ip_address')
        service = pattern.get('service')._id
        return [f"Gain knowledge to gain access to service ({service}) on {ip}"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check to identify an asset with a HTTP service.
        """
        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service', protocol='http')
        pattern = asset.directed_path_to(service)
        return kg.get_matching(pattern)

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use GoSpider to crawl the web app then filter the results with a
        keyword search.
        """
        ip = pattern.get('asset').get('ip_address')
        result = shell("gospider", ["-s", f"http://{ip}"])
        return result

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Update the knowledge graph with discovered web pages.
        """
        asset = pattern.get('asset')
        ip = asset.get('ip_address')
        drive = Entity('Drive', alias='drive', location=f'http://{ip}')
        service = pattern.get('service')
        sd_pattern = service.with_edge(Relationship('accesses')).with_node(drive)

        changes: StateChangeSequence = []
        changes.append((pattern, 'merge_if_not_match', sd_pattern))

        regex_pattern = r'http[s]?://[^\s\]\n]+'
        all_http_files = list(sorted(set(re.findall(regex_pattern, output.stdout))))
        uuid = artefacts.search("login_page_keywords.txt")[0]

        with artefacts.open(uuid, "r") as file:
            keywords = [w for w in file.read().split('\n') if w]
        files = [file for file in all_http_files if any(k in file.lower() for k in keywords)]

        for file in files:
            file_loc = file.lstrip(f'http://{ip}')
            path_list = file_loc.split('/')
            filename = path_list.pop()

            match_pattern = pattern[0].with_edge(Relationship('accesses')).with_node(drive)
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


class HttpGetAllPages(Action):
    """
    Use GoSpider to crawl a web app and identify any pages it finds.
    """

    def __init__(self):
        super().__init__("HttpGetAllPages", "T1083 File and Directory Discovery", "TA0007 Discovery", ["quiet", "fast"])
        self.noise = 0.9
        self.impact = 0.1

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        ip = pattern.get('asset').get('ip_address')
        service = pattern.get('service')._id
        return [f"Gain knowledge to gain access to {ip} via HTTP service ({service})"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check to identify an asset with a HTTP service.
        """
        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service', protocol='http')
        pattern = asset.directed_path_to(service)
        return kg.get_matching(pattern)

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use GoSpider to crawl the web app
        """
        ip = pattern.get('asset').get('ip_address')
        result = shell(
            "feroxbuster",
            [
                "-u",
                f"http://{ip}",
                "-w",
                "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
                "-f",
                "--threads",
                100,
                "-C",
                404,
                "-d",
                2,
                "--silent",
            ],
        )
        return result

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Update the knowledge graph with discovered web pages.
        """
        asset = pattern.get('asset')
        ip = asset.get('ip_address')
        drive = Entity('Drive', alias='drive', location=f'http://{ip}')
        service = pattern.get('service')
        sd_pattern = service.with_edge(Relationship('accesses')).with_node(drive)

        changes: StateChangeSequence = []
        changes.append((pattern, 'merge_if_not_match', sd_pattern))

        regex_pattern = r'http[s]?://[^\s\]\n]+'
        all_http_files = list(sorted(set(re.findall(regex_pattern, output.stdout))))

        for file in all_http_files:
            file_loc = file.lstrip(f'http://{ip}')
            path_list = file_loc.split('/')
            filename = path_list.pop()

            match_pattern = pattern[0].with_edge(Relationship('accesses')).with_node(drive)
            merge_pattern = drive

            for index, path in enumerate(path_list):
                directory = Entity('Directory', alias=f'directory{index}', dirname=path)
                merge_pattern = merge_pattern.with_edge(Relationship('has', direction='r')).with_node(directory)
                changes.append((match_pattern, "merge_if_not_match", merge_pattern))
                match_pattern = match_pattern.with_edge(Relationship('has', direction='r')).with_node(directory)
                merge_pattern = directory

            if filename:
                merge_pattern = merge_pattern.with_edge(Relationship('has', direction='r')).with_node(
                    Entity(type='File', filename=filename)
                )
            changes.append((match_pattern, "merge_if_not_match", merge_pattern))

        return changes


actions = [
    HttpGobuster(),
    # HttpDownloadFile(),
    HttpGetLoginPages(),
    HttpGetAllPages(),
]
