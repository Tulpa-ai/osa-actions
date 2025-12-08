from pathlib import Path
from typing import Any, Union

import sh

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionError, ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation


class ScpGetFile(Action):
    """
    Represents an action to retrieve a file from a remote system via SCP (Secure Copy Protocol)
    in the context of cybersecurity attack simulations.
    """

    def __init__(self):
        """
        Initializes the ScpGetFile action with a specific attack identifier,
        tactic, and technique information.
        """
        super().__init__("ScpGetFile", "T1083", "TA0007", ["loud", "fast"])
        self.noise = 0.3
        self.impact = 1
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for ScpGetFile.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_ScpGetFile", description="Input motif for ScpGetFile"
        )

        input_motif.add_template(
            entity=Entity('Asset', alias='asset'),
            template_name="existing_asset",
        )

        input_motif.add_template(
            entity=Entity('OpenPort', alias='port'),
            template_name="existing_port",
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity('Service', alias='service', protocol='ssh'),
            template_name="existing_service",
            relationship_type="is_running",
            match_on="existing_port",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity('Credentials', alias='credentials'),
            template_name="existing_credentials",
            relationship_type="secured_with",
            match_on="existing_service",
        )

        input_motif.add_template(
            entity=Entity('Drive', alias='drive'),
            template_name="existing_drive",
            relationship_type="accesses",
            match_on="existing_asset",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity('File', alias='file', filename='id_rsa'),
            template_name="existing_file",
            relationship_type="directed_path",
            match_on="existing_drive",
            pattern_alias='filepath',
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for ScpGetFile.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_ScpGetFile", description="Output motif for ScpGetFile"
        )

        output_motif.add_template(
            template_name="discovered_file",
            entity=Entity('File', alias='file', filename='id_rsa'),
            expected_attributes=["artefact_id"],
            operation=StateChangeOperation.UPDATE,
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """Generates the expected outcome for the action based on the provided pattern.

        Args:
            pattern (Pattern): A pattern object containing asset and file information.

        Returns:
            list[str]: A list describing the expected result of retrieving the file.
        """
        ip = pattern.get('asset').get('ip_address')
        path_pattern: Pattern = pattern.get('filepath')
        filepath = Path('/')
        for g_obj in path_pattern:
            if g_obj.type == 'Directory':
                filepath = filepath / g_obj.get('dirname')
            if g_obj.type == 'File':
                filepath = filepath / g_obj.get('filename')
        return [f"Get {filepath} from {ip}"]

    def get_target_query(self) -> Query:
        """
        Identifies target patterns within the knowledge graph that match conditions for
        performing the SCP action.

        Args:
            kg (GraphDB): A knowledge graph object representing system entities and relationships.

        Returns:
            list[Union[Pattern, MultiPattern]]: A list of matching patterns representing valid targets.
        """
        query = self.input_motif.get_query()
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Executes the SCP command to retrieve a specified file from a remote system.

        Args:
            sessions (SessionManager): Manages SSH session connections.
            artefacts (ArtefactManager): Manages artefacts resulting from the SCP action.
            pattern (Pattern): A pattern object describing the target file and session details.

        Returns:
            str: The result of the SCP command execution.
        """
        ip = pattern.get('asset').get('ip_address')
        portnum = pattern.get('openport').get('number')
        username = pattern.get('credentials').get('username')
        path_pattern: Pattern = pattern.get('filepath')
        filepath = Path('/')
        for g_obj in path_pattern:
            if g_obj.type == 'Directory':
                filepath = filepath / g_obj.get('dirname')
            if g_obj.type == 'File':
                filepath = filepath / g_obj.get('filename')
        filename = path_pattern[-1].get('filename')
        uuid = artefacts.placeholder(filename)
        artefact_path = artefacts.get_path(uuid)

        command, argv = None, []
        if password := pattern.get('credentials').get('password'):
            command = "sshpass"
            argv = [
                "-p",
                f"{password}",
                "scp",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                f"{username}@{ip}:{filepath}",
                f"{artefact_path}",
            ]
        elif ssh_key_file := pattern.get('credentials').get('key_file'):
            command = "scp"
            argv = [
                "-P",
                f"{portnum}",
                "-i",
                f"{ssh_key_file}",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                f"{username}@{ip}:{filepath}",
                f"{artefact_path}",
            ]

        if command is not None:
            try:
                res = shell(command, argv)
            except sh.ErrorReturnCode:
                raise ActionExecutionError(
                    f"Error when trying to run {command} {argv} to download '{filepath}' from {ip}"
                )
            res.artefacts[filename] = uuid
            return res
        raise ActionExecutionError("ScpGetFile: cannot run action, unable to extract the necessary values")

    def parse_output(self, output: ActionExecutionResult, pattern: Pattern) -> dict:
        """
        Parse the output of the ScpGetFile action.
        """
        filename = pattern.get('filepath')[-1].get('filename')
        return {
            "file_id": output.artefacts[filename]
        }

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate the output motif for ScpGetFile.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        file_from_pattern = pattern.get('filepath')[-1]
        file_from_pattern.alias = 'file'
        changes.append(
            self.output_motif.instantiate(
                template_name="discovered_file",
                match_on_override=file_from_pattern,
                artefact_id=discovered_data["file_id"]
            )
        )
        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Captures the state change in the knowledge graph after the SCP action.

        Args:
            artefacts (ArtefactManager): Manages artefacts related to the SCP action.
            pattern (Pattern): The pattern describing the targeted asset and file.
            output (ActionExecutionResult): The result of the SCP command execution.

        Returns:
            StateChangeSequence: A sequence of changes made to the system state.
        """
        discovered_data = self.parse_output(output, pattern)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
