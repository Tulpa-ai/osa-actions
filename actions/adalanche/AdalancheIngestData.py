"""Actions to ingest Active Directory data into a local Adalanche instance.

This module defines the AdalancheIngestData action which collects AD data
using provided credentials, stores it on disk, starts an Adalanche analyze
server bound to a chosen port and registers an AdalancheRepository in the
session manager for subsequent queries.
"""
from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.activedirectory import AdalancheRepository
from action_state_interface.exec import ActionExecutionError, ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation
from Session import SessionManager
from utils.httpclient import SimpleHttpClient


class AdalancheIngestData(Action):
    """Action that collects Active Directory data and loads it into Adalanche.

    The action uses credentials and target computer information from the
    supplied pattern to run the `adalanche collect activedirectory` command,
    writes datapath and port artefacts, starts an analyze server and registers
    the resulting AdalancheRepository in the provided SessionManager.
    """

    def __init__(self):
        """Initialize the AdalancheIngestData action, building motifs and metadata."""
        super().__init__("AdalancheIngestData", "T1043", "TA0007", [])

        self.noise = 0.1
        self.impact = 0
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """Construct and return the input motif for the action.

        The motif requires a DomainPartition, a controlling ComputerAccount and
        Credentials linked to the domain.

        Returns:
            ActionInputMotif: the configured input motif.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_AdalancheIngestData",
            description="Input requirements for the Adalanche Ingest Data action",
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
        """Construct and return the output motif used to update the domain.

        The output motif defines an update to the DomainPartition with
        attributes indicating data_loaded and the registered Adalanche client.

        Returns:
            ActionOutputMotif: the configured output motif.
        """
        output_motif = ActionOutputMotif(
            name="adalanche_ingest_data_output",
            description="Template to update the domain",
        )

        output_motif.add_template(
            entity=Entity('DomainPartition', alias='domain'),
            template_name="updated_domain",
            operation=StateChangeOperation.UPDATE,
            expected_attributes=["data_loaded", "adalanche_client"],
        )

        return output_motif

    def expected_outcome(self, pattern) -> list[str]:
        """Describe the high-level expected outcome for a given pattern.

        Args:
            pattern: Pattern-like mapping with 'creds', 'computer' and 'domain'.

        Returns:
            list[str]: Human-readable descriptions of the expected outcome.
        """
        username = pattern.get('creds').get('username')
        controller_ip = pattern.get('computer').get('ip_address')
        domain = pattern.get('domain').get('label')

        return [
            f"Use credentials for {username}@{domain} to fetch AD data from the DC at {controller_ip}",
            "then load the data into Adalanche before restarting Adalanche to make it available for queries.",
        ]

    def get_target_query(self) -> Query:
        """Return the KG query selecting target domains, computers and credentials.

        The input motif's query is returned with all results requested.

        Returns:
            Query: configured Query object.
        """
        query = self.input_motif.get_query()
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """Execute the ingestion: collect AD data, start analyze server and register repository.

        Args:
            sessions: SessionManager used to register the AdalancheRepository.
            artefacts: ArtefactManager used to create datapath and port artefacts.
            pattern: Pattern-like mapping providing creds, computer and domain.

        Returns:
            ActionExecutionResult or ActionExecutionError: result of collection or an error.
        """
        creds = pattern.get('creds')
        computer_account = pattern.get('computer')

        domain = pattern.get('domain').get('label')
        username = creds.get('username')
        password = creds.get('password')
        dc_ip = computer_account.get('ip_address')
        authdomain = computer_account.get('name')

        datapath = f"{domain}_ad_data"
        data_uuid = artefacts.placeholder(datapath)
        data_file_path = artefacts.get_path(data_uuid)

        fetch = shell(
            "adalanche",
            [
                "--datapath",
                data_file_path,
                "collect",
                "activedirectory",
                "--domain",
                domain,
                "--authdomain",
                authdomain,
                "--username",
                username,
                "--password",
                password,
                "--server",
                dc_ip,
            ],
        )

        if not fetch:
            return ActionExecutionError(
                f"Failed to dump AD data from domain {domain} on {dc_ip} using {username}:{password}"
            )

        port = 8989
        ad_port_keys = artefacts.search("adalanche_port")
        for key in ad_port_keys:
            file_path = artefacts.get_path(key)
            with open(file_path, 'r') as f:
                stored_port = int(f.readline().strip())
                if stored_port >= port:
                    port = stored_port + 1

        portpath = "adalanche_port"
        port_uuid = artefacts.placeholder(portpath)
        port_file_path = artefacts.get_path(port_uuid)
        with open(port_file_path, 'w') as f:
            f.write(str(port))

        ad_repo = AdalancheRepository(
            http_client=SimpleHttpClient(),
            api_routes={
                "aql": f"http://localhost:{port}/api/aql/analyze",
                "details": f"http://localhost:{port}/api/details/",
            },
        )
        sessions.add_named_session(f"adalanche_client_{port}", ad_repo)

        return shell(
            "adalanche",
            ["--datapath", data_file_path, "analyze", "--bind", f"0.0.0.0:{port}", "--nobrowser"],
            background=True,
        )

    def parse_output(self, output: ActionExecutionResult) -> dict[str, str]:
        """Extract the client name from the action execution output.

        The convention expects the analyze bind address in the command list such
        that the port can be extracted.

        Args:
            output: ActionExecutionResult returned by function().

        Returns:
            dict[str, str]: mapping with 'client_name' key for the registered session.
        """
        port = output.command[-2].split(":")[1]
        return {"client_name": f"adalanche_client_{port}"}

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict[str, list[str]]) -> StateChangeSequence:
        """Instantiate output motif changes based on discovered data.

        Args:
            pattern: original Pattern-like mapping used as context for matching.
            discovered_data: mapping returned by parse_output().

        Returns:
            StateChangeSequence: list of state change operations to apply to the KG.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        if not discovered_data:
            return changes

        domain_from_pattern = pattern.get('domain')
        domain_update = self.output_motif.instantiate(
            "updated_domain",
            match_on_override=domain_from_pattern,
            data_loaded=True,
            adalanche_client=discovered_data["client_name"],
        )
        changes.append(domain_update)

        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """Capture and return state changes derived from an execution output.

        This combines parse_output() and populate_output_motif().

        Args:
            artefacts: ArtefactManager instance (unused here but kept for signature).
            pattern: original Pattern-like mapping.
            output: ActionExecutionResult produced by function().

        Returns:
            StateChangeSequence: the sequence of state changes to apply.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
