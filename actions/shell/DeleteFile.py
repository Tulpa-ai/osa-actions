from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif


class DeleteFile(Action):
    """
    Implementation of T1561.001 Disk Wipe - Disk Content Wipe (File Deletion).

    This action deletes files on Linux systems using rm.
    """

    # Shell-capable protocols for running commands
    SHELL_PROTOCOLS = ["ssh", "shell", "busybox"]

    def __init__(self):
        super().__init__("DeleteFile", "T1561.001", "TA0040", ["loud", "fast"])
        self.noise = 1.0
        self.impact = 1.0
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for DeleteFile.

        Requires:
        - A File entity to delete
        - A shell session (SSH, shell, busybox) on the same asset (for running commands)
        """
        input_motif = ActionInputMotif(
            name="InputMotif_DeleteFile", description="Input motif for DeleteFile"
        )

        # Asset (required for session and file location)
        input_motif.add_template(
            entity=Entity("Asset", alias="asset"),
            template_name="existing_asset",
        )

        # Drive entity (ensures file is on the same asset)
        input_motif.add_template(
            entity=Entity("Drive", alias="drive"),
            template_name="existing_drive",
            relationship_type="directed_path",
            match_on="existing_asset",
        )

        # Directory entity (required for file path construction)
        input_motif.add_template(
            entity=Entity("Directory", alias="directory"),
            template_name="existing_directory",
            relationship_type="directed_path",
            match_on="existing_drive",
        )

        # File entity to delete
        input_motif.add_template(
            entity=Entity("File", alias="file"),
            template_name="existing_file",
            relationship_type="directed_path",
            match_on="existing_directory",
        )

        # Session from any service on the asset
        input_motif.add_template(
            entity=Entity("OpenPort", alias="session_port"),
            template_name="existing_session_port",
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity("Service", alias="session_service"),
            template_name="existing_session_service",
            relationship_type="is_running",
            match_on="existing_session_port",
            invert_relationship=True,
        )

        # Session executing on the service
        input_motif.add_template(
            entity=Entity("Session", alias="session", active=True),
            template_name="existing_session",
            relationship_type="executes_on",
            match_on="existing_session_service",
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for DeleteFile.

        This action does not create any output entities.
        """
        return ActionOutputMotif(
            name="OutputMotif_DeleteFile", description="Output motif for DeleteFile"
        )

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        asset = pattern.get("asset")
        asset_ip = asset.get("ip_address") if asset else "unknown"
        file_entity = pattern.get("file")
        filename = file_entity.get("filename") if file_entity else "unknown"
        session = pattern.get("session")._id
        session_service = pattern.get("session_service")
        session_service_protocol = (
            session_service.get("protocol") if session_service else "unknown"
        )

        return [
            f"Delete file {filename} on {asset_ip} using {session_service_protocol} session ({session})"
        ]

    def get_target_query(self) -> Query:
        """
        Get target patterns for file deletion.
        This action targets files that have active shell sessions available.
        Only shows action for files where active is True or not set (not False).
        """
        query = self.input_motif.get_query()
        # Target shell-capable service protocols (for running commands)
        query.where(
            self.input_motif.get_template(
                "existing_session_service"
            ).entity.protocol.is_in(self.SHELL_PROTOCOLS)
        )
        # Ensure session is shell-capable
        query.where(
            self.input_motif.get_template("existing_session").entity.protocol.is_in(
                self.SHELL_PROTOCOLS
            )
        )
        # Only show action for active files (exclude files where active is False)
        file_template = self.input_motif.get_template("existing_file")
        query.where_not(file_template.entity.active == False)
        query.ret_all()
        return query

    def _get_file_path(self, pattern: Pattern, live_session) -> str:
        """
        Find the absolute file path by searching the filesystem using find.

        Since Directory entities in the KG may be missing path components,
        we search the filesystem using 'find' to locate the file by filename
        and return its absolute path.
        """
        file_entity = pattern.get("file")
        if not file_entity:
            return ""

        filename = file_entity.get("filename")
        if not filename:
            return ""

        # Escape filename for use in find command (handle special characters)
        escaped_filename = (
            filename.replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
        )

        # Run find command from root to locate the file
        find_cmd = f'cd / && find "/" -type f -name "{escaped_filename}" 2>/dev/null'
        find_output = live_session.run_command(find_cmd)

        # Parse all lines of output - first line might be command echo, rest are paths
        found_paths = []
        for line in find_output.split("\n"):
            line = line.strip()
            # Skip empty lines and non-absolute paths
            if line and line.startswith("/") and "/" in line[1:]:
                # Skip lines that look like command echoes (contain the find command itself)
                if "find" not in line.lower() and "cd" not in line.lower():
                    found_paths.append(line)

        if found_paths:
            return found_paths[0]

        # File not found
        return ""

    def _escape_path_for_shell(self, file_path: str) -> str:
        """
        Escape a file path for safe use in shell commands within double quotes.
        Escapes backslashes and double quotes.
        """
        return file_path.replace("\\", "\\\\").replace('"', '\\"')

    def _create_error_result(
        self, message: str, session_id: str
    ) -> ActionExecutionResult:
        """
        Create an error ActionExecutionResult.
        """
        return ActionExecutionResult(
            command=[], stdout=message, exit_status=1, session=session_id
        )

    def function(
        self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern
    ) -> ActionExecutionResult:
        """
        Execute file deletion.

        Finds the file using find, then deletes it. Verifies deletion succeeded
        by checking if the file still exists after deletion.
        """
        tulpa_session = pattern.get("session")
        tulpa_session_id = tulpa_session.get("id")
        live_session = sessions.get_session(tulpa_session_id)

        if not live_session:
            return self._create_error_result(
                "No active session available", tulpa_session_id
            )

        file_path = self._get_file_path(pattern, live_session)

        if not file_path:
            return self._create_error_result("File not found", tulpa_session_id)

        # Verify file exists BEFORE deletion
        escaped_path = self._escape_path_for_shell(file_path)
        check_cmd = f'test -f "{escaped_path}" && echo "EXISTS" || echo "NOT_EXISTS"'
        check_output = live_session.run_command(check_cmd)

        # Check if file actually exists
        file_exists = False
        for line in check_output.split("\n"):
            line = line.strip()
            if line == "EXISTS":
                file_exists = True
                break

        if not file_exists:
            return self._create_error_result(
                f"File does not exist: {file_path}", tulpa_session_id
            )

        # Delete the file
        delete_cmd = f'rm -f "{escaped_path}" 2>/dev/null'
        delete_output = live_session.run_command(delete_cmd)

        # Verify file was actually deleted by checking if it still exists
        verify_cmd = (
            f'test -f "{escaped_path}" && echo "STILL_EXISTS" || echo "DELETED"'
        )
        verify_output = live_session.run_command(verify_cmd)

        # Check if file was actually deleted
        still_exists = False
        for line in verify_output.split("\n"):
            line = line.strip()
            if line == "STILL_EXISTS":
                still_exists = True
                break

        if still_exists:
            stdout = (
                f"Failed to delete file: {file_path}\n{delete_output}\n{verify_output}"
            )
            exit_status = 1
        else:
            stdout = f"Deleted file: {file_path} (using rm)\n{delete_output}"
            exit_status = 0

        return ActionExecutionResult(
            command=["rm"],
            stdout=stdout,
            exit_status=exit_status,
            session=tulpa_session_id,
        )

    def parse_output(self, output: ActionExecutionResult) -> dict:
        """
        Parse the output of the DeleteFile action.
        Success is determined by exit_status (0 = success, 1 = failure).
        """
        success = output.exit_status == 0
        deleted_files = []

        # Extract file path from success message if present
        for line in output.stdout.split("\n"):
            line = line.strip()
            if line.startswith("Deleted file:") and "(using" in line:
                # Extract path from "Deleted file: /path/to/file (using rm)"
                parts = line.split("Deleted file:")
                if len(parts) > 1:
                    file_part = parts[1].split("(using")[0].strip()
                    if file_part:
                        deleted_files.append(file_part)

        return {"deleted": success, "success": success, "deleted_files": deleted_files}

    def populate_output_motif(
        self, pattern: Pattern, discovered_data: dict
    ) -> StateChangeSequence:
        """
        Populate the output motif for DeleteFile.

        Updates the File entity to mark it as inactive (active: False) after deletion.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        # If file was successfully deleted, mark it as inactive
        if discovered_data.get("success"):
            file_entity = pattern.get("file")
            if file_entity:
                # Create updated file entity with active: False
                updated_file = file_entity.copy()
                updated_file.set("active", False)
                changes.append((pattern, "update", updated_file))

        return changes

    def capture_state_change(
        self,
        artefacts: ArtefactManager,
        pattern: Pattern,
        output: ActionExecutionResult,
    ) -> StateChangeSequence:
        """
        Capture state changes from file deletion.

        Marks the deleted File entity as inactive (active: False) in the graph.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
