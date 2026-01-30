from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import parse_crackmapexec_users_output, shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from motifs import ActionInputMotif, ActionOutputMotif
from Session import SessionManager


class CMEUserReconnaissance(Action):
    """
    Discovers users using crackmapexec user scan.
    """

    def __init__(self):
        super().__init__("CMEUserReconnaissance", "T1043", "TA0007", [])

        self.noise = 0.1
        self.impact = 0
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for CMEUserReconnaissance.

        Defines the required domain partition and a computer account entity with controller=True
        for the scan to be applicable.

        Returns:
            ActionInputMotif: Input motif requiring a DomainPartition and a ComputerAccount (controller)
        """
        input_motif = ActionInputMotif(
            name="InputMotif_CMEUserReconnaissance",
            description="Input requirements for CME user scan on DC",
        )
        input_motif.add_template(entity=Entity('DomainPartition', alias='domain'), template_name="existing_domain")
        input_motif.add_template(
            entity=Entity('ComputerAccount', alias='account', controller=True),
            template_name="existing_account",
            match_on="existing_domain",
            relationship_type="belongs_to",
        )
        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif templates for CMEUserReconnaissance.

        Defines templates for discovered User entities belonging to a DomainPartition.

        Returns:
            ActionOutputMotif: Output motif with user discovery templates
        """
        output_motif = ActionOutputMotif(
            name="cme_user_reconnaissance_output",
            description="Templates for discovered Users belonging to a DomainPartition",
        )

        output_motif.add_template(
            entity=Entity('User', alias='user'),
            template_name="discovered_user",
            match_on=Entity('DomainPartition'),
            relationship_type='belongs_to',
        )

        return output_motif

    def expected_outcome(self, pattern) -> list[str]:
        """
        Discovers domain controller IP addresses using crackmapexec and updates existing ComputerAccount entities.
        """
        account = pattern.get('account')
        ip = account.get('ip_address') if account else 'unknown'
        return [f"Use crackmapexec to discover users on the domain controller running on {ip}"]

    def get_target_query(self) -> Query:
        """
        Build and return the query used to select targets for this action.

        The query is based on the input motif and targets domain controllers,
        represented as ComputerAccount entities with controller=True that belong
        to a DomainPartition, for user enumeration with crackmapexec.
        """
        query = self.input_motif.get_query()
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use crackmapexec to scan for SMB services and identify domain controllers.
        """
        account = pattern.get('account')
        ip = account.get('ip_address') if account else None

        if not ip:
            return ActionExecutionResult(
                command=["/usr/local/bin/cme"], stderr="No ip address found in account pattern", exit_status=1
            )

        # Run crackmapexec SMB scan on the subnet
        cme_command = "/usr/local/bin/cme"
        cme_args = ["smb", ip, "--users"]

        try:
            result = shell(cme_command, cme_args, ok_code=[0, 1])
            return result
        except Exception as e:
            error_msg = f"Error running crackmapexec: {str(e)}"
            return ActionExecutionResult(command=[cme_command] + cme_args, stderr=error_msg, exit_status=1)

    def parse_output(self, output: ActionExecutionResult) -> dict[str, list[str]]:
        """
        Parse cme output to extract discovered IP addresses and their computer accounts.

        Args:
            output: ActionExecutionResult containing cme scan output

        Returns:
            Dict mapping ip addresses to computer account details
        """
        if output.exit_status != 0:
            return {}

        # Parse crackmapexec output
        # Format: SMB         192.168.56.11   445    WINTERFELL       north.sevenkingdoms.local\brandon.stark                  Brandon Stark
        cme_output = output.stdout.strip()

        if not cme_output:
            return {}

        discoveries = parse_crackmapexec_users_output(cme_output)
        return {d['username']: d for d in discoveries}

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict[str, list[str]]) -> StateChangeSequence:
        """
        Instantiate output motif changes based on discovered data.

        Args:
            pattern: original Pattern-like mapping used as context for matching.
            discovered_data: mapping returned by parse_output().

        Returns:
            StateChangeSequence: list of state change operations to apply to the KG.
        """
        self.output_motif.reset_context()
        domain = pattern.get('domain')
        changes: StateChangeSequence = []

        if not discovered_data:
            return changes

        for username, details in discovered_data.items():
            new_user = self.output_motif.instantiate(
                "discovered_user",
                match_on_override=domain,
                name=username,
                description=details["description"],
                domain=details["domain"],
            )
            changes.append(new_user)

        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Capture state changes from the CMEUserReconnaissance execution.
        This will update the ComputerAccount entities with the domain controller IP information from the SMB scan.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
