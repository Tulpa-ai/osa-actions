import re
from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionResult
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from artefacts.ArtefactManager import ArtefactManager
from Session import SessionManager

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