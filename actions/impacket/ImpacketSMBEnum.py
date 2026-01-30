import time
from typing import Any

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import parse_smb_shares, shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from motifs import ActionInputMotif, ActionOutputMotif
from Session import SessionManager


class ImpacketSMBEnum(Action):
    """
    ImpacketSMBEnum action that enumerates SMB shares using CrackMapExec
    for lateral movement with cracked credentials.

    This action requires:
    - A User entity with cracked credentials (password_cracked = true)
    - The user must have valid domain credentials for lateral movement
    """

    def __init__(self):
        super().__init__("ImpacketSMBEnum", "T1021.002", "TA0008", [])
        self.noise = 0.3
        self.impact = 0.4
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for ImpacketSMBEnum.

        Query for Users entities and their associated ComputerAccounts using creds.

        Returns:
            ActionInputMotif: Input motif requiring related DomainPartition, ComputerAccount (controller=True) and Credentials entities
        """
        input_motif = ActionInputMotif(
            name="InputMotif_ImpacketSMBEnum",
            description="Input requirements for Impacket SMB Enum command",
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
        Build the output motif for ImpacketSMBEnum.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_ImpacketSMBEnum", description="Output motif for ImpacketSMBEnum"
        )

        output_motif.add_template(
            template_name="discovered_share",
            entity=Entity("Share", alias="share"),
            relationship_type="hosts",
            match_on=Entity("ComputerAccount"),
            invert_relationship=True,
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return the expected outcome of the ImpacketSMBEnum action.
        """
        username = pattern.get('creds').get('username')
        smb_ip = pattern.get('computer').get('ip_address')
        domain = pattern.get('domain').get('label')

        return [
            f"Enumerate SMB shares on domain controller at {smb_ip} using credentials for {username}@{domain}",
            "Discover available shares (IPC$, ADMIN$, C$, SYSVOL, NETLOGON) for lateral movement",
            "Identify accessible resources and potential attack paths",
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
        Execute cme smb command to enumerate shares for lateral movement.
        """
        creds = pattern.get('creds')
        computer_account = pattern.get('computer')

        domain = pattern.get('domain').get('label')
        username = creds.get('username')
        password = creds.get('password')
        dc_ip = computer_account.get('ip_address')

        # Validate that we have proper string values, not boolean True
        if not isinstance(username, str) or not isinstance(password, str):
            return ActionExecutionResult(
                command=[],
                stdout="",
                stderr=f"Invalid user data: username={username}, password={password}",
                exit_status=1,
                logs=["ImpacketSMBEnum failed: user data contains boolean values instead of strings"],
            )

        # Construct the cme smb command for share enumeration
        # Format: cme smb <ip> -u <username> -p <password> -d <domain> --shares
        command_args = ["smb", dc_ip, "-u", username, "-p", password, "-d", domain, "--shares"]

        # Execute the command and capture output
        exec_result = shell("cme", command_args)

        if exec_result.exit_status != 0:
            return ActionExecutionResult(
                command=command_args,
                stdout=exec_result.stdout,
                stderr=f"Failed to enumerate SMB shares: {exec_result.stderr}",
                exit_status=1,
                logs=[f"ImpacketSMBEnum failed for {username}@{domain}"],
            )

        # Check for errors in stdout/stderr even if exit_status is 0
        error_indicators = [
            "Error in bindRequest",
            "Error in searchRequest",
            "invalidCredentials",
            "Connection timed out",
            "[-] Error",
            "[-] [Errno ",
            "Authentication failed",
            "Login failed",
            "Access denied",
            "Insufficient access rights",
            "Connection refused",
            "No route to host",
        ]

        output_text = (exec_result.stdout or "") + (exec_result.stderr or "")
        if any(error in output_text for error in error_indicators):
            return ActionExecutionResult(
                command=command_args,
                stdout=exec_result.stdout,
                stderr=exec_result.stderr,
                exit_status=1,
                logs=[f"ImpacketSMBEnum command failed with error: {output_text}"],
            )

        return exec_result

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Capture state changes from the ImpacketSMBEnum execution.
        Update user to mark SMB enumeration as completed.
        """
        changes: StateChangeSequence = []

        # If the command failed, don't process any state changes
        if output.exit_status != 0:
            return changes

        # Parse the command output to verify success
        output_text = (output.stdout or "") + (output.stderr or "")

        # Look for success indicators in the command output
        success_indicators = [
            "SMB",  # cme shows SMB connection info
            "shares",  # Share enumeration results
            "IPC$",  # Common share found
            "ADMIN$",  # Common share found
            "C$",  # Common share found
            "SYSVOL",  # Domain share
            "NETLOGON",  # Domain share
        ]

        if any(indicator in output_text for indicator in success_indicators):
            username = pattern.get('creds').get('username')
            computer_account = pattern.get('computer')

            # Parse SMB shares from the output
            shares = parse_smb_shares(output_text)

            # Create Share entities for each discovered share
            for share_info in shares:
                new_share = self.output_motif.instantiate(
                    "discovered_share",
                    match_on_override=computer_account,
                    name=share_info['name'],
                    share_type="smb",
                    permissions=share_info['permissions'],
                    description=share_info['remark'],
                    host=computer_account.get('name'),
                    host_ip=computer_account.get('ip_address'),
                    domain=computer_account.get('domain'),
                    enumerated_by=username,
                    enumeration_timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                    is_accessible=True,
                )
                changes.append(new_share)

        return changes

    def parse_output(self, output: ActionExecutionResult) -> dict[str, Any]:
        """
        Placeholder implementation for actions not using the new architecture.
        """
        return {}

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict[str, list[str]]) -> StateChangeSequence:
        """
        Placeholder implementation for actions not using the new architecture.
        """
        return []
