"""Action that queries an Adalanche repository for ComputerAccount entities.

This module defines the AdalancheFetchComputerAccounts action which queries a
previously-registered AdalancheRepository session to fetch computer account
data, serializes it and provides methods to parse and convert that output into
KG state changes via an output motif.
"""
from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.activedirectory import ComputerAccountListModel
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation
from Session import SessionManager


class AdalancheFetchComputerAccounts(Action):
    """Action to fetch ComputerAccount entities from an Adalanche repository.

    The action expects a DomainPartition with data_loaded=True and a registered
    adalanche client name stored in the domain entity. It queries the named
    session for computer accounts and returns serialized results as the action
    output. parse_output() and populate_output_motif() convert the output into
    KG state changes.
    """

    def __init__(self):
        """Initialize the fetch action, building motifs and metadata."""
        super().__init__("AdalancheFetchComputerAccounts", "T1018", "TA0007", [])

        self.noise = 0
        self.impact = 0
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """Construct and return the input motif for fetching computer accounts.

        Returns:
            ActionInputMotif: Input motif requiring a domain with data_loaded=True.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_AdalancheFetchComputerAccounts",
            description="Input requirements for the AdalancheFetchComputerAccounts action",
        )
        input_motif.add_template(
            entity=Entity('DomainPartition', alias='domain', data_loaded=True), template_name="existing_domain"
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """Construct and return the output motif used to create/update ComputerAccount entities.

        Returns:
            ActionOutputMotif: the configured output motif with expected attributes.
        """
        output_motif = ActionOutputMotif(
            name="adalanche_fetch_computer_accounts_output",
            description="Template to create/update ComputerAccounts",
        )

        output_motif.add_template(
            entity=Entity('DomainPartition', alias='domain', data_loaded=True), template_name="existing_domain"
        )

        output_motif.add_template(
            entity=Entity('ComputerAccount', alias='computer'),
            template_name="updated_computer",
            match_on="existing_domain",
            relationship_type='belongs_to',
            operation=StateChangeOperation.UPSERT,
        )

        return output_motif

    def expected_outcome(self, pattern) -> list[str]:
        """Return a human-readable expected outcome for the provided pattern.

        Args:
            pattern: Pattern-like mapping containing the 'domain' entity.

        Returns:
            list[str]: outcome descriptions including the domain label.
        """
        return [f"Gain knowledge of Active Directory Computer Accounts on {pattern.get('domain').get('label')}"]

    def get_target_query(self) -> Query:
        """Create and return the KG query selecting target DomainPartitions for this action.

        Returns:
            Query: the input motif query configured to return all matches.
        """
        query = self.input_motif.get_query()
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """Execute the action by querying the registered Adalanche session for computers.

        Args:
            sessions: SessionManager containing named AdalancheRepository sessions.
            artefacts: ArtefactManager (unused in this action but kept for signature).
            pattern: Pattern-like mapping that includes the domain entity with 'adalanche_client'.

        Returns:
            ActionExecutionResult: includes command metadata and serialized stdout or an error exit status.
        """
        domain = pattern.get('domain')
        adalanche_client = domain.get('adalanche_client')
        ad_client = sessions.get_named_session(adalanche_client)

        ad_command = "Query Active Directory data source for 'ComputerAccount' entities"

        try:
            computers = ad_client.computer_accounts()
        except RuntimeError:
            return ActionExecutionResult(
                command=[ad_command], stderr="Error while trying to talk to AD client", exit_status=1
            )

        return ActionExecutionResult(
            command=[ad_command],
            stdout=ComputerAccountListModel.dump_json(computers),
        )

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """Convert execution output into a sequence of KG state changes.

        Args:
            artefacts: ArtefactManager (kept for signature compatibility).
            pattern: Pattern-like mapping used for context when instantiating templates.
            output: ActionExecutionResult produced by function().

        Returns:
            StateChangeSequence: list of instantiated output motif changes.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes

    def parse_output(self, output: ActionExecutionResult) -> dict[str, list]:
        """Parse the ActionExecutionResult stdout into structured computer account objects.

        Args:
            output: ActionExecutionResult from function().

        Returns:
            dict[str, list]: mapping with key 'computer_accounts' containing a list of validated ComputerAccount objects.
        """
        computer_accounts = ComputerAccountListModel.validate_json(output.stdout)
        return {"computer_accounts": computer_accounts}

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict[str, list[str]]) -> StateChangeSequence:
        """Instantiate output motif templates for each discovered computer account.

        Args:
            parsed_output: result of parse_output containing 'computer_accounts'.
            pattern: Pattern or MultiPattern used as context for instantiation.

        Returns:
            StateChangeSequence: list of instantiated updates to apply to the KG.
        """
        changes: StateChangeSequence = []
        domain_from_pattern = pattern.get('domain')
        for computer_account in discovered_data["computer_accounts"]:
            computer_update = self.output_motif.instantiate(
                "updated_computer",
                name=computer_account.name,
                match_on_override=domain_from_pattern,
                set_properties={
                    'distinguished_name': computer_account.distinguished_name,
                    'domain': computer_account.domain,
                    'domain_context': computer_account.domain_context,
                    'is_account_active': computer_account.is_account_active,
                    'is_account_enabled': computer_account.is_account_enabled,
                    'is_domain_controller_account': computer_account.is_domain_controller_account,
                    'operating_system': computer_account.operating_system,
                    'operating_system_version': computer_account.operating_system_version,
                },
            )
            changes.append(computer_update)

        return changes
