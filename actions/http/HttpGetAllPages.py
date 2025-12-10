import re
from typing import Union, Any

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionResult
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from artefacts.ArtefactManager import ArtefactManager
from Session import SessionManager

class HttpGetAllPages(Action):
    """
    Use Feroxbuster to crawl a web app and identify any pages it finds.
    """

    def __init__(self):
        super().__init__("HttpGetAllPages", "T1083", "TA0007", ["quiet", "fast"])
        self.noise = 0.9
        self.impact = 0.1

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        ip = pattern.get('asset').get('ip_address')
        service = pattern.get('service')._id
        return [f"Gain knowledge to gain access to {ip} via HTTP service ({service})"]

    def get_target_query(self) -> Query:
        """
        get_target_patterns check to identify an asset with a HTTP service.
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
        Use Feroxbuster to crawl the web app with a hardcoded recursion depth of 2 
        (we'll make it possible to configure actions in future, in the meantime if you want to change this you'll need to create a clone of this action)
        Crawls twice: once with slashes appended (-f) and once without, so that we don't miss things on weirdly configured web services
        """
        ip = pattern.get('asset').get('ip_address')
        
        res1 = shell(
            "feroxbuster",
            [
                "-u", f"http://{ip}",
                "-w", "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
                "--threads", 100,
                "-C", 404,
                "-d", 2,
                "--silent",
            ],
        )
        res1_urls = set(res1.stdout.split("\n"))
        
        res2 = shell(
            "feroxbuster",
            [
                "-u", f"http://{ip}",
                "-w", "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
                "--threads", 100,
                "-C", 404,
                "-d", 2,
                "--silent",
                "-f",
            ],
        )
        
        res2_urls = set(res2.stdout.split("\n"))
        res1.stdout = "\n".join(res1_urls.union(res2_urls))
        return res1

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

    def parse_output(self, output: ActionExecutionResult) -> dict[str, Any]:
        """
        Placeholder implementation for actions not using the new architecture.
        """
        return {}

    def populate_output_motif(
        self, discovered_data: dict[str, Any], pattern: Union[Pattern, MultiPattern]
    ) -> StateChangeSequence:
        """
        Placeholder implementation for actions not using the new architecture.
        """