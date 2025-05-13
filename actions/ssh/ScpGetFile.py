from pathlib import Path
from typing import Any, Union

import sh

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionError, ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager


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
        super().__init__("ScpGetFile", "T1083 File and Directory Discovery", "TA0007 Discovery", ["loud", "fast"])
        self.noise = 0.3
        self.impact = 1

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
        asset = Entity('Asset', alias='asset')
        has = Relationship('has')
        port = Entity('OpenPort', alias='openport')
        is_running = Relationship('is_running')
        service = Entity('Service', alias='service', protocol='ssh')
        secured_with = Relationship('secured_with', direction='l')
        credentials = Entity('Credentials', alias='credentials')
        file = Entity(type='File', alias='file', filename='id_rsa')
        drive = Entity('Drive', alias='drive')
        file_pattern = drive.directed_path_to(file)
        file_pattern.set_alias('filepath')
        match_pattern = (
            asset.with_edge(has)
            .with_node(port)
            .with_edge(is_running)
            .with_node(service)
            .with_edge(secured_with)
            .with_node(credentials)
            .combine(asset.connects_to(drive))
            .combine(file_pattern)
        )
        query = Query()
        query.match(match_pattern)
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

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Captures the state change in the knowledge graph after the SCP action.

        Args:
            kg (GraphDB): The knowledge graph representing the current state of the system.
            artefacts (ArtefactManager): Manages artefacts related to the SCP action.
            pattern (Pattern): The pattern describing the targeted asset and file.
            output (ActionExecutionResult): The result of the SCP command execution.

        Returns:
            StateChangeSequence: A sequence of changes made to the system state.
        """

        changes: StateChangeSequence = []

        as_pattern = pattern[0]
        file_pattern = pattern.get('filepath')
        file_pattern[-1].alias = 'file'
        match_pattern = as_pattern.combine(file_pattern)
        file = file_pattern[-1].copy()
        file.alias = 'file'
        file.set('artefact_id', output.artefacts[file.get('filename')])

        changes.append((match_pattern, 'update', file))

        return changes
