from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import parse_crackmapexec_output, shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from motifs import ActionInputMotif, ActionOutputMotif
from Session import SessionManager


class CMESMBReconnaissance(Action):
    """
    Discovers domain controller IP addresses using crackmapexec SMB scan and updates existing ComputerAccount entities.
    This action scans for SMB services to identify domain controllers and adds their IP addresses
    to existing ComputerAccount entities that are already linked to DomainPartition entities.
    """

    def __init__(self):
        super().__init__("CMESMBReconnaissance", "T1043", "TA0007", [])

        self.noise = 0.1
        self.impact = 0
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for CMESMBReconnaissance.

        Defines the required subnet entity that must exist for the scan to be applicable.

        Returns:
            ActionInputMotif: Input motif requiring a Subnet entity
        """
        input_motif = ActionInputMotif(
            name="InputMotif_CMESMBReconnaissance",
            description="Input requirements for CME SMB scan on subnet",
        )
        input_motif.add_template(
            entity=Entity('Subnet', alias='subnet'), template_name="subnet", expected_attributes=["network_address"]
        )
        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif templates for CMESMBReconnaissance.

        Defines templates for:
        - Discovered domain partitions (linked to subnets via hosts relationship)
        - Discovered assets (linked to subnets via belongs_to relationship)
        - Discovered computer accounts (linked to domain partitions via belongs_to relationship)

        Returns:
            ActionOutputMotif: Output motif with domain, asset, and computer account templates
        """
        subnet = Entity('Subnet')

        output_motif = ActionOutputMotif(
            name="cme_netbios_scan_output",
            description="Templates for discovered Assets (0-N instances) and ComputerAccounts (1 for each Asset)",
        )

        output_motif.add_template(
            entity=Entity('DomainPartition', alias='domain'),
            template_name="discovered_domain",
            match_on=subnet,
            relationship_type='hosts',
            invert_relationship=True,
        )

        output_motif.add_template(
            entity=Entity('Asset', alias='asset'),
            template_name="discovered_asset",
            match_on=subnet,
            relationship_type='belongs_to',
        )

        output_motif.add_template(
            entity=Entity('ComputerAccount', alias='account'),
            template_name="discovered_account",
            match_on="discovered_domain",
            relationship_type='belongs_to',
        )

        return output_motif

    def expected_outcome(self, pattern) -> list[str]:
        """
        Discovers domain controller IP addresses using crackmapexec and updates existing ComputerAccount entities.
        """
        subnet = pattern.get('subnet')
        network_address = subnet.get('network_address') if subnet else 'unknown'
        return [f"Use crackmapexec to discover assets, domain controllers and AD accounts on {network_address}"]

    def get_target_query(self) -> Query:
        """
        Target subnets with network addresses. The action will discover domain controllers
        on these subnets and link them to ComputerAccount entities if they exist.
        """
        query = self.input_motif.get_query()
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use crackmapexec to scan for SMB services and identify domain controllers.
        """
        subnet = pattern.get('subnet')
        network_address = subnet.get('network_address') if subnet else None

        if not network_address:
            return ActionExecutionResult(
                command=["/usr/local/bin/cme"], stderr="No network address found in subnet pattern", exit_status=1
            )

        # Run crackmapexec SMB scan on the subnet
        cme_command = "/usr/local/bin/cme"
        cme_args = ["smb", network_address]

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
        # Format: SMB         IP_ADDRESS   445    HOSTNAME    [*] OS_INFO (name:HOSTNAME) (domain:DOMAIN) (signing:True/False) (SMBv1:True/False)
        cme_output = output.stdout.strip()

        if not cme_output:
            return {}

        discoveries = parse_crackmapexec_output(cme_output)
        return {d['ip_address']: d for d in discoveries}

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
        subnet = pattern.get('subnet')
        changes: StateChangeSequence = []

        if not discovered_data:
            return changes

        for ip, details in discovered_data.items():
            new_domain = self.output_motif.instantiate(
                "discovered_domain", match_on_override=subnet, label=details.get('domain')
            )
            changes.append(new_domain)
            new_asset = self.output_motif.instantiate("discovered_asset", match_on_override=subnet, ip_address=ip)
            changes.append(new_asset)
            account_change = self.output_motif.instantiate(
                "discovered_account",
                ip_address=ip,
                name=details.get('hostname'),
                domain=details.get('domain'),
                controller=details.get('signing', False),
            )
            changes.append(account_change)

        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Capture state changes from the CMESMBReconnaissance execution.
        This will update the ComputerAccount entities with the domain controller IP information from the SMB scan.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
