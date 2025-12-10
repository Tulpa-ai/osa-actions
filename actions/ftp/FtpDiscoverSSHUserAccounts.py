import os
from typing import Any, Union
from action_state_interface.action import Action, StateChangeSequence
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation


class FtpDiscoverSSHUserAccounts(Action):
    def __init__(self):
        super().__init__(
            "FtpDiscoverSSHUserAccounts", "T1083", "TA0007", ["quiet", "fast"]
        )
        self.noise = 0.2
        self.impact = 0.2
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for FtpDiscoverSSHUserAccounts.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_FtpDiscoverSSHUserAccounts",
            description="Input motif for FtpDiscoverSSHUserAccounts"
        )

        input_motif.add_template(
            entity=Entity('Asset', alias='asset'),
            template_name="existing_asset",
        )

        input_motif.add_template(
            entity=Entity('OpenPort', alias='ftp_port'),
            template_name="existing_ftp_port",
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity('Service', alias='ftp_service', protocol='ftp'),
            template_name="existing_ftp_service",
            relationship_type="is_running",
            match_on="existing_ftp_port",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity('Drive', alias='drive'),
            template_name="existing_drive",
            relationship_type="accesses",
            match_on="existing_ftp_service",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity('Directory', alias='directory', dirname='.ssh'),
            template_name="existing_directory",
            relationship_type="directed_path",
            match_on="existing_drive",
        )

        input_motif.add_template(
            entity=Entity('OpenPort', alias='ssh_port'),
            template_name="existing_ssh_port",
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity('Service', alias='ssh_service', protocol='ssh'),
            template_name="existing_ssh_service",
            relationship_type="is_running",
            match_on="existing_ssh_port",
            invert_relationship=True,
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for FtpDiscoverSSHUserAccounts.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_FtpDiscoverSSHUserAccounts",
            description="Output motif for FtpDiscoverSSHUserAccounts"
        )

        # Template for SSH service entity
        # This will be instantiated with match_on_override to match on asset_port pattern
        # match_on is set to Entity('OpenPort') as a placeholder (will be overridden during instantiation)
        output_motif.add_template(
            entity=Entity('Service', alias='ssh_service', protocol='ssh'),
            template_name="ssh_service",
            match_on=Entity('OpenPort'),  # Placeholder - will be overridden with asset_port pattern
            relationship_type='is_running',
            invert_relationship=True,
            operation=StateChangeOperation.MERGE_IF_NOT_MATCH
        )

        # Template for SSH user entities
        # This matches on the ssh_service template (by name)
        # Relationship: ssh_service -[is_client]-> user
        output_motif.add_template(
            entity=Entity('User', alias='user'),
            template_name="ssh_user",
            match_on="ssh_service",
            relationship_type='is_client',
            operation=StateChangeOperation.MERGE_IF_NOT_MATCH
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        ip = pattern.get('asset').get('ip_address')
        service = pattern.get('ftp_service')._id
        return [f"Use the file system using the ftp service ({service}) on {ip} to infer SSH user accounts"]

    def get_target_query(self) -> Query:
        query = self.input_motif.get_query()
        query.ret_all()
        return query

    def function(self, sessions, artefacts, pattern: Pattern) -> str:
        ip = pattern.get('asset').get('ip_address')
        uuid = artefacts.search(f'FTP-directories-on-{ip}')[0]
        with artefacts.open(uuid, "rb") as f:
            all_files = [line.decode("utf-8").rstrip('\n') for line in f.readlines()]
        return all_files

    def parse_output(self, output: Any) -> dict:
        """
        Parse the output of the FtpDiscoverSSHUserAccounts action.
        """
        ssh_users = set()
        for path in output:
            parts = path.split(os.sep)
            if '.ssh' in parts:
                index = parts.index('.ssh')
                if index > 0:
                    ssh_users.add(parts[index - 1])

        return {
            "ssh_users": list(ssh_users),
        }

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate output motif templates using the motif instantiation system.
        
        This method:
        1. Resets the output motif context for this execution
        2. Builds the asset_port pattern from the input pattern
        3. Instantiates the ssh_service template if SSH users are discovered
        4. Instantiates the ssh_user template for each discovered user
        
        Args:
            pattern: Input pattern containing the asset
            discovered_data: Dictionary containing parsed SSH user data
            
        Returns:
            StateChangeSequence containing all state changes
        """
        # TODO: This action needs to be modified so that the added user is linked to both the FTP and SSH services
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        ssh_service = pattern.get('ssh_service')
        # Only create SSH service if we discovered users
        if len(discovered_data["ssh_users"]) > 0:
            ssh_service_change = self.output_motif.instantiate(
                "ssh_service",
                full_pattern_override=pattern,
            )
            changes.append(ssh_service_change)
            for user in discovered_data["ssh_users"]:
                user_change = self.output_motif.instantiate(
                    "ssh_user",
                    match_on_override=ssh_service,
                    username=user
                )
                changes.append(user_change)
        
        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: Any
    ) -> StateChangeSequence:
        """Capture and update the knowledge graph based on discovered SSH user accounts.

        This function processes the output from the FTP discovery, extracts SSH user accounts,
        and updates the knowledge graph by linking users to the SSH service running on the asset.

        Args:
            artefacts (ArtefactManager): Manages stored artefacts.
            pattern (Pattern): Contains asset-related information.
            output (list[str]): The list of discovered file paths.

        Returns:
            StateChangeSequence: A sequence of state changes to be applied to the knowledge graph.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
