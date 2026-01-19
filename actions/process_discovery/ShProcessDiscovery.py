from pathlib import Path
import uuid

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionResult, ActionExecutionError
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, MultiPattern, Pattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif


def extract_process_names(file_content: str) -> set[str]:
    """
    Extract unique process names from mixed `ps` and `ps aux` output.
    """
    process_names = set()

    for line in file_content.splitlines():
        line = line.strip()

        # Skip empty lines and headers
        if not line:
            continue
        if line.startswith(("PID ", "USER ", "%CPU", "TTY")):
            continue

        parts = line.split()

        # ps output: PID TTY TIME CMD
        if len(parts) >= 4 and parts[0].isdigit():
            cmd = parts[3]

        # ps aux output: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
        elif len(parts) >= 11:
            cmd = parts[10]

        else:
            continue

        # Extract executable name only (strip paths & args)
        executable = Path(cmd).name
        process_names.add(executable)

    return process_names


class ShProcessDiscovery(Action):
    """
    Discover running processes on a target system using shell commands.

    This action executes `ps` and `ps aux` on a live session to enumerate
    running processes, stores the output as an artefact, parses the results,
    and records discovered processes in the state graph.

    MITRE ATT&CK:
        - Technique: T1057 (Process Discovery)
        - Tactic: TA0004 (Discovery)
    """

    def __init__(self):
        """
        Initialise the process discovery action.

        Sets metadata such as noise and impact scores, and builds the
        input and output motifs required for execution and state updates.
        """
        super().__init__("ShProcessDiscovery", "T1057", "TA0004", ["quiet", "fast"])
        self.noise = 0.5
        self.impact = 0.8
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for process discovery.

        The input motif requires:
            - An existing Asset
            - An OpenPort on that Asset
            - A Service running on that Port
            - A Session executing on that Service
            - A User associated with the Service
            - A Permission associated with the User

        Returns:
            ActionInputMotif: Configured input motif for this action.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_ShProcessDiscovery",
            description="Input motif for ShProcessDiscovery"
        )

        input_motif.add_template(
            template_name="existing_asset",
            entity=Entity("Asset", alias="asset"),
        )

        input_motif.add_template(
            template_name="existing_port",
            entity=Entity("OpenPort", alias="port"),
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )

        input_motif.add_template(
            template_name="existing_service",
            entity=Entity("Service", alias="service"),
            relationship_type="is_running",
            match_on="existing_port",
            invert_relationship=True,
        )

        input_motif.add_template(
            template_name="existing_session",
            entity=Entity("Session", alias="session", active=True),
            relationship_type="executes_on",
            match_on="existing_service",
        )

        input_motif.add_template(
            template_name="existing_user",
            entity=Entity("User", alias="user"),
            relationship_type="is_client",
            match_on="existing_service",
        )

        input_motif.add_template(
            template_name="existing_permission",
            entity=Entity("Permission", alias="permission"),
            relationship_type="has",
            match_on="existing_user",
            invert_relationship=True,
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for process discovery.

        The output motif models newly discovered Process entities
        associated with an Asset.

        Returns:
            ActionOutputMotif: Configured output motif for this action.
        """
        asset = Entity('Asset', alias='asset')
        output_motif = ActionOutputMotif(
            name="OutputMotif_ShProcessDiscovery",
            description="Output motif for ShProcessDiscovery"
        )
        output_motif.add_template(
            entity=Entity('Process', alias='proc'),
            template_name="discovered_process",
            match_on=asset,
            relationship_type='has',
            invert_relationship=True
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Describe the expected outcome of this action.

        Args:
            pattern (Pattern): Matched input pattern for the action.

        Returns:
            list[str]: Human-readable descriptions of expected state changes.
        """
        user = pattern.get("user").get("username")
        session = pattern.get("session")._id
        service = pattern.get("service")._id
        return [
            f"Discover running processes on service ({service}) using session ({session}) as user {user}"
        ]

    def get_target_query(self) -> Query:
        """
        Build the query used to select valid execution targets.

        Returns:
            Query: Query returning all entities required by the input motif.
        """
        query = self.input_motif.get_query()
        query.where(
            self.input_motif.get_template('existing_session').entity.protocol.is_in([
                'ssh', 'shell', 'busybox'
            ])
        )
        query.ret_all()
        return query

    def function(
        self,
        sessions: SessionManager,
        artefacts: ArtefactManager,
        pattern: MultiPattern,
    ) -> ActionExecutionResult:
        """
        Execute process discovery on the target session.

        Runs `ps` and `ps aux` on the live session and writes the combined
        output to an artefact file.

        Args:
            sessions (SessionManager): Manager for active sessions.
            artefacts (ArtefactManager): Manager for artefact storage.
            pattern (MultiPattern): Matched execution pattern.

        Returns:
            ActionExecutionResult: Execution metadata and generated artefacts.
        """
        tulpa_session = pattern.get("session")
        tulpa_session_id = tulpa_session.get("id")
        live_session = sessions.get_session(tulpa_session_id)

        if live_session is None:
            raise ActionExecutionError(
                f"Session {tulpa_session_id} not found in SessionManager"
            )

        cmd1 = "ps"
        cmd2 = "ps aux"
        
        output1 = live_session.run_command(cmd1)
        output2 = live_session.run_command(cmd2)
        combined_output = output1 + "\n" + output2
        
        unique_id = str(uuid.uuid4())
        filename = f"{self.name}_output_session_{tulpa_session_id}_{unique_id}"
        key = artefacts.placeholder(filename)
        output_file = artefacts.get_path(key)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(combined_output)

        return ActionExecutionResult(
            command=[cmd1, cmd2],
            artefacts={'output_file': key},
            session=tulpa_session_id,
            stdout=combined_output
        )

    def parse_output(
        self, output: ActionExecutionResult, artefacts: ArtefactManager
    ) -> dict:
        """
        Parse the process discovery output artefact.

        Args:
            output (ActionExecutionResult): Result of action execution.
            artefacts (ArtefactManager): Artefact manager.

        Returns:
            dict: Parsed discovery data containing process names.

        Raises:
            ActionExecutionError: If the expected artefact is missing.
        """
        try:
            with artefacts.open(output.artefacts["output_file"], 'r') as f:
                content = f.read()
        except KeyError as e:
            raise ActionExecutionError(e) from e

        processes = extract_process_names(content)
        return {'processes': processes}

    def populate_output_motif(
        self, pattern: Pattern, discovered_data: dict
    ) -> StateChangeSequence:
        """
        Populate the output motif with discovered processes.

        Args:
            pattern (Pattern): Execution pattern.
            discovered_data (dict): Parsed discovery data.

        Returns:
            StateChangeSequence: State changes representing discovered processes.
        """
        self.output_motif.reset_context()
        asset = pattern.get('asset')
        changes: StateChangeSequence = []

        for proc_name in discovered_data['processes']:
            add_process_change = self.output_motif.instantiate(
                "discovered_process",
                match_on_override=asset,
                name=proc_name,
            )
            changes.append(add_process_change)

        return changes

    def capture_state_change(
        self,
        artefacts: ArtefactManager,
        pattern: Pattern,
        output: ActionExecutionResult,
    ) -> StateChangeSequence:
        """
        Populate the output motif with discovered processes.

        Creates Process entities and associates them with the target Asset.

        Args:
            artefacts (ArtefactManager): Artefact manager.
            pattern (Pattern): Execution pattern.
            output (ActionExecutionResult): Result of action execution.

        Returns:
            StateChangeSequence: State changes representing discovered processes.
        """
        discovered_data = self.parse_output(output, artefacts)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
