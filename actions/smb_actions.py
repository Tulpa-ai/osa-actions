import re
from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from Session import SessionManager


class SMBShareEnumeration(Action):
    """
    SMBShareEnumeration is an action class that enumerates SMB shares on a target asset.
    """

    def __init__(self):
        super().__init__("SMBUserEnumeration", "T1078 Valid Accounts", "TA0001 Initial Access", ["quiet", "fast"])
        self.noise = 0.2
        self.impact = 0.1

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return the expected outcome of an action based on the provided pattern.
        """
        return [
            f"Search for SMB sharepoints with anonymous logins on {pattern.get('asset').get('ip_address')} : {pattern.get('service').get('protocol')}"
        ]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        Retrieves target patterns from the knowledge graph.

        This method constructs a pattern to match assets that have an open port 445
        running a service with the protocol 'microsoft-ds'. It then queries the
        knowledge graph to find all matches for this pattern.
        """
        asset = Entity('Asset', alias='asset')
        port = Entity('OpenPort', alias='port', number=445)
        service = Entity('Service', alias='service', protocol='microsoft-ds')
        pattern = (
            asset.with_edge(Relationship('has', direction='r'))
            .with_node(port)
            .with_edge(Relationship('is_running', direction='r'))
            .with_node(service)
        )
        matches = kg.get_matching(pattern)
        return matches

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Executes an SMB client command to list shares on a remote server without a password.
        """
        asset = pattern.get('asset')
        ip_address = asset.get('ip_address')
        stdout = shell(
            "smbclient",
            ["-L", f"//{ip_address}", "-N"],
        )
        return stdout

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Captures state changes from the given smb sharepoint output and attaches the smb drives to the smb service.
        """
        regex = re.compile(r'^\s*(\S+)\s+Disk')

        changes: StateChangeSequence = []
        for line in output.stdout.splitlines():
            match = regex.match(line)
            if match:
                sharename = match.group(1)
                new_drive = Entity(
                    'Drive', alias='drive', location=f'SMB://{pattern.get("asset").get("ip_address")}/{sharename}'
                )
                changes.append((None, "merge", new_drive))
                asset_and_new_drive_multipattern = new_drive.combine(pattern)
                service_to_drive_pattern = (
                    pattern.get('service').with_edge(Relationship('accesses', direction='r')).with_node(new_drive)
                )
                changes.append((asset_and_new_drive_multipattern, "merge", service_to_drive_pattern))
        return changes


actions = [SMBShareEnumeration()]
