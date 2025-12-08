import re
from typing import Any, Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from kg_api.query import Query
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
        "gobuster",
        ["dir", "-u", url, "-w", wordlist, "-o", output, "-b", ignore, "--timeout", "20s", "--no-color"]
    )
    res.artefacts["json_report"] = output
    return res

class HttpGobuster(Action):
    """
    Use gobuster command to scan HTTP service and list files and folders.
    """

    def __init__(self):
        super().__init__("HttpGobuster", "T1083", "TA0007", ["quiet", "fast"])
        self.noise = 0.8
        self.impact = 0.4

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        ip = pattern.get('asset').get('ip_address')
        service = pattern.get('service')._id
        return [f"Gain knowledge to gain access to {ip} via HTTP service ({service})"]

    def get_target_query(self) -> Query:
        """
        get_target_patterns check looking for HTTP services, drives and directories.
        """
        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service', protocol='http')
        pattern = asset.directed_path_to(service)
        query = Query()
        query.match(pattern)
        query.ret_all()
        return query

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

    def parse_output(self, output: ActionExecutionResult) -> dict[str, Any]:
        """
        Placeholder implementation for actions not using the new architecture.
        """
        return {}

    def populate_output_motif(
        self, parsed_output: dict[str, Any], pattern: Union[Pattern, MultiPattern]
    ) -> StateChangeSequence:
        """
        Placeholder implementation for actions not using the new architecture.
        """
        return []