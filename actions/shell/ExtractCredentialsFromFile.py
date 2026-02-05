import re
from typing import Any

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation


_LINE_RE = re.compile(r"^\s*([^:#\s]+)\s*:\s*([^\s#]+)\s*$")
_PASSWORD_ONLY_RE = re.compile(r"^\s*([^\s#]+)\s*$")


class ExtractCredentialsFromFile(Action):
    """
    Parse a plaintext credential file (lines like 'username:password' or password-only) and add discovered credentials into the KG.

    This is intended for testing/lab scenarios where credentials may be discovered in files (e.g. from FTP anonymous access),
    then need to be represented in the KG so other actions can use them.
    
    Supports two formats:
    - username:password (standard format)
    - password (password-only format, username will be empty)
    """

    def __init__(self):
        super().__init__("ExtractCredentialsFromFile", "T1552", "TA0006", ["quiet", "fast"])
        self.noise = 0.1
        self.impact = 0.2
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        input_motif = ActionInputMotif(
            name="InputMotif_ExtractCredentialsFromFile",
            description="Input motif for ExtractCredentialsFromFile",
        )


        input_motif.add_template(entity=Entity("Asset", alias="asset"), template_name="existing_asset")

        input_motif.add_template(
            entity=Entity("OpenPort", alias="port"),
            template_name="existing_port",
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity("Service", alias="service"),
            template_name="existing_service",
            relationship_type="is_running",
            match_on="existing_port",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity("File", alias="file"),
            template_name="existing_file",
            expected_attributes=["artefact_id"],
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        output_motif = ActionOutputMotif(
            name="OutputMotif_ExtractCredentialsFromFile",
            description="Output motif for ExtractCredentialsFromFile",
        )

        output_motif.add_template(
            entity=Entity("Credentials", alias="credentials"),
            template_name="discovered_credentials",
            match_on=Entity("Service", alias="service"),
            relationship_type="secured_with",
            operation=StateChangeOperation.MERGE_IF_NOT_MATCH,
        )

        output_motif.add_template(
            entity=Entity("User", alias="user"),
            template_name="discovered_user",
            match_on=Entity("Service", alias="service"),
            relationship_type="is_client",
            invert_relationship=False,
            operation=StateChangeOperation.MERGE_IF_NOT_MATCH,
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        service = pattern.get("service")._id
        file_id = pattern.get("file")._id
        return [f"Extract credentials from file ({file_id}) and attach them to service ({service})"]

    def get_target_query(self) -> Query:
        query = self.input_motif.get_query()
        query.ret_all()
        return query

    @staticmethod
    def _parse_credential_line(line: str) -> dict[str, str] | None:
        """
        Parse a line that may contain credentials.
        Returns a dict with 'username' and 'password' keys, or None if line doesn't contain credentials.
        """
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        m = _LINE_RE.match(line)
        if m:
            return {"username": m.group(1), "password": m.group(2)}

        m = _PASSWORD_ONLY_RE.match(line)
        if m and ":" not in line:
            return {"username": "", "password": m.group(1)}
        
        return None

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        file_ent = pattern.get("file")
        artefact_id = file_ent.get("artefact_id")
        file_path = artefacts.get_path(artefact_id)

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()

        discovered: list[dict[str, str]] = []
        for line in raw.splitlines():
            cred = self._parse_credential_line(line)
            if cred:
                discovered.append(cred)

        cred_lines = [
            f"{c['username']}:{c['password']}" if c["username"] else c["password"]
            for c in discovered
        ]
        stdout_lines = [f"Parsed {len(discovered)} credential entries:"] + cred_lines
        return ActionExecutionResult(
            command=["parse-creds", file_path],
            stdout="\n".join(stdout_lines),
            artefacts={"source_file_artefact_id": artefact_id},
            logs=(
                [f"Parsed {len(discovered)} credential entries from a file artefact and will write them to the KG."]
                + [f"  {line}" for line in cred_lines]
            ),
        )

    def parse_output(self, output: ActionExecutionResult, pattern: Pattern, artefacts: ArtefactManager) -> list[dict[str, str]]:
        artefact_id = pattern.get("file").get("artefact_id")
        file_path = artefacts.get_path(artefact_id)
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()

        discovered: list[dict[str, str]] = []
        for line in raw.splitlines():
            cred = self._parse_credential_line(line)
            if cred:
                discovered.append(cred)
        return discovered

    def populate_output_motif(self, pattern: Pattern, discovered_data: Any) -> StateChangeSequence:
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        service = pattern.get("service")
        source_file_artefact_id = pattern.get("file").get("artefact_id")

        for cred in discovered_data:
            username = cred["username"]
            password = cred["password"]

            changes.append(
                self.output_motif.instantiate(
                    template_name="discovered_credentials",
                    match_on_override=service,
                    username=username,
                    password=password,
                    source_artefact_id=source_file_artefact_id,
                )
            )

            if username:
                changes.append(
                    self.output_motif.instantiate(
                        template_name="discovered_user",
                        match_on_override=service,
                        username=username,
                    )
                )

        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        discovered = self.parse_output(output, pattern, artefacts)
        return self.populate_output_motif(pattern, discovered)

