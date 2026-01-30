from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.activedirectory import PersonListModel
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation
from Session import SessionManager


class AdalancheFetchUsers(Action):
    """
    Fetches all 'Person' entities from the AD repo and adds them to the KG as
    User entities.
    """

    def __init__(self):
        super().__init__("AdalancheFetchUsers", "T1087", "TA007", [])

        self.noise = 0
        self.impact = 0
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """Construct and return the input motif for fetching domain partitions.

        Returns:
            ActionInputMotif: Input motif requiring a domain with data_loaded=True.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_AdalancheFetchUsers",
            description="Input requirements for the Adalanche Fetch Users action",
        )
        input_motif.add_template(
            entity=Entity('DomainPartition', alias='domain', data_loaded=True), template_name="existing_domain"
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """Construct and return the output motif used to create/update User entities.

        Returns:
            ActionOutputMotif: the configured output motif with expected attributes.
        """
        output_motif = ActionOutputMotif(
            name="adalanche_fetch_users_output",
            description="Template to create or update User entities discovered from Active Directory",
        )

        output_motif.add_template(
            entity=Entity('DomainPartition', alias='domain', data_loaded=True), template_name="existing_domain"
        )

        output_motif.add_template(
            entity=Entity('User', alias='user'),
            template_name="updated_user",
            match_on="existing_domain",
            relationship_type="belongs_to",
            operation=StateChangeOperation.UPSERT,
        )

        return output_motif

    def expected_outcome(self, pattern) -> list[str]:
        """
        Discovers User entities using the Active Directory data source.
        """
        return [f"Gain knowledge of Active Directory accounts on {pattern.get('domain').get('label')}"]

    def get_target_query(self) -> Query:
        """Create and return the KG query selecting target DomainPartitions for this action.

        Returns:
            Query: the input motif query configured to return all matches.
        """
        query = self.input_motif.get_query()
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Uses the AD client to fetch all available users, which get
        serialised and returned from the AER.
        """
        domain = pattern.get('domain')
        adalanche_client = domain.get('adalanche_client')
        ad_client = sessions.get_named_session(adalanche_client)

        ad_command = "Query Active Directory data source for 'people' entities"

        try:
            people = ad_client.people()
        except RuntimeError:
            return ActionExecutionResult(
                command=[ad_command], stderr="Error while trying to talk to AD client", exit_status=1
            )

        return ActionExecutionResult(
            command=[ad_command],
            stdout=PersonListModel.dump_json(people),
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
        """Parse the ActionExecutionResult stdout into structured user objects.

        Args:
            output: ActionExecutionResult from function().

        Returns:
            dict[str, list]: mapping with key 'people' containing a list of validated User objects.
        """
        people = PersonListModel.validate_json(output.stdout)
        return {"people": people}

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict[str, list[str]]) -> StateChangeSequence:
        """Instantiate output motif templates for each discovered user.

        Args:
            parsed_output: result of parse_output containing 'people'.
            pattern: Pattern or MultiPattern used as context for instantiation.

        Returns:
            StateChangeSequence: list of instantiated updates to apply to the KG.
        """
        changes: StateChangeSequence = []
        domain_from_pattern = pattern.get('domain')
        for person in discovered_data["people"]:
            user_update = self.output_motif.instantiate(
                "updated_user",
                name=person.name,
                match_on_override=domain_from_pattern,
                set_properties={
                    "distinguished_name": person.distinguished_name if person.distinguished_name else "",
                    "domain_context": person.domain_context if person.domain_context else "",
                    "member_of": person.member_of,
                    "is_account_active": person.is_account_active,
                    "is_account_enabled": person.is_account_enabled,
                    "is_account_kerberoastable": person.is_account_kerberoastable,
                    "password_never_expires": person.password_never_expires,
                },
            )
            changes.append(user_update)

        return changes
