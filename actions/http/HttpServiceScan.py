import re
from typing import Any, Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, Pattern, Relationship, MultiPattern
from kg_api.query import Query
from Session import SessionManager

class HttpServiceScan(Action):
    """
    Implementation of DIRB scan against an HTTP service.
    """

    def __init__(self):
        super().__init__("HttpServiceScan", "T1083", "TA0007", ["loud", "fast"])
        self.noise = 0.3
        self.impact = 0

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        ip = pattern.get('asset').get('ip_address')
        service = pattern.get('service')._id
        return [f"Gain knowledge to gain access to {ip} via service ({service})"]

    def get_target_query(self) -> Query:
        """
        get_target_patterns check looking for assets which are running an HTTP service.
        """
        asset = Entity('Asset', alias='asset')
        http_service = Entity('Service', alias='service', protocol='http')
        match_pattern = asset.directed_path_to(http_service)
        negate_pattern = http_service.directed_path_to(Entity('Directory'))
        query = Query()
        query.match(match_pattern)
        query.where_not(negate_pattern)
        query.where(http_service.self_spawned.is_null())
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use shell function from action_utils to perform DIRB scan.
        """
        ip = pattern.get('asset').get('ip_address')
        uuid = artefacts.search('small.txt')[0]
        wordlist_path = artefacts.get_path(uuid)
        scan_report = shell("dirb", [f"http://{ip}", wordlist_path])
        return scan_report

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Add Drive entities and Directory entities to knowledge graph.
        """
        directory_pattern = r"==> DIRECTORY: (http://\d{1,3}(?:\.\d{1,3}){3}/(\S+))/"
        url_pattern = r"\+ (http://\d{1,3}(?:\.\d{1,3}){3}/(\S+)) \(CODE:\d+\|SIZE:\d+\)"

        # Find all directories and individual URLs
        directories = re.findall(directory_pattern, output.stdout)
        urls = re.findall(url_pattern, output.stdout)

        # Combine both lists
        dirb_data = directories + urls

        service: Entity = pattern.get('service')
        asset: Entity = pattern.get('asset')
        ip = asset.get('ip_address')

        drive = Entity(type='Drive', alias='drive', location=f'HTTP://{ip}')

        merge_pattern = service.with_edge(Relationship(type='accesses')).with_node(drive)
        changes: StateChangeSequence = [(pattern, "merge_if_not_match", merge_pattern)]

        match_pattern = asset.directed_path_to(service).directed_path_to(drive)

        for dir in dirb_data:
            directory = Entity(type='Directory', alias='dir', dirname=dir[1])

            merge_pattern = drive.with_edge(Relationship(type='has')).with_node(directory)
            changes.append((match_pattern, "merge", merge_pattern))

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