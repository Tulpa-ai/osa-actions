from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation


class CompressFile(Action):
    """
    Compress a file into a tar archive on a Linux system.
    
    This action collects a file from the knowledge graph and compresses it
    into a tar.gz archive using the tar command. Linux only.
    """

    # Shell-capable protocols for running commands
    SHELL_PROTOCOLS = ["ssh", "shell"]

    def __init__(self):
        super().__init__("CompressFile", "T1560", "TA0010", ["quiet", "fast"])
        self.noise = 0.3
        self.impact = 0.4
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for CompressFiles.
        Requires: Asset, Session (SSH/shell), and File entities to compress.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_CompressFile",
            description="Input motif for CompressFile"
        )

        input_motif.add_template(
            template_name="existing_asset",
            entity=Entity('Asset', alias='asset'),
        )

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

        input_motif.add_template(
            entity=Entity("Session", alias="session", active=True),
            template_name="existing_session",
            relationship_type="executes_on",
            match_on="existing_session_service",
        )

        input_motif.add_template(
            entity=Entity("Drive", alias="drive"),
            template_name="existing_drive",
            relationship_type="directed_path",
            match_on="existing_asset",
        )

        input_motif.add_template(
            entity=Entity("Directory", alias="directory"),
            template_name="existing_directory",
            relationship_type="directed_path",
            match_on="existing_drive",
        )

        input_motif.add_template(
            entity=Entity("File", alias="file"),
            template_name="existing_file",
            relationship_type="directed_path",
            match_on="existing_directory",
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for CompressFiles.
        Creates a File entity for the compressed archive.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_CompressFile",
            description="Output motif for CompressFile"
        )

        output_motif.add_template(
            template_name="compressed_archive",
            entity=Entity('File', alias='archive'),
            expected_attributes=["artefact_id", "filename", "compressed"],
            operation=StateChangeOperation.MERGE_IF_NOT_MATCH,
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        asset = pattern.get("asset")
        asset_ip = asset.get("ip_address") if asset else "unknown"
        file_entity = pattern.get("file")
        filename = file_entity.get("filename") if file_entity else "unknown"

        return [
            f"Compress {filename} on {asset_ip} into a tar.gz archive"
        ]

    def get_target_query(self) -> Query:
        """
        Get target patterns for file compression.
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
        Execute file compression.

        Finds the file using find, then compresses it. Verifies compression succeeded
        by checking if the archive file exists after compression.
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

        # Verify file exists BEFORE compression
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

        # Create archive name
        file_entity = pattern.get("file")
        filename = file_entity.get("filename") if file_entity else "file"
        archive_name = f"compressed_{filename}_{tulpa_session_id}.tar.gz"
        archive_path = f"/tmp/{archive_name}"
        escaped_archive_path = self._escape_path_for_shell(archive_path)

        # Compress the file
        compress_cmd = f'tar -czf "{escaped_archive_path}" "{escaped_path}" 2>/dev/null'
        compress_output = live_session.run_command(compress_cmd)

        # Verify archive was actually created by checking if it exists
        verify_cmd = (
            f'test -f "{escaped_archive_path}" && echo "ARCHIVE_EXISTS" || echo "ARCHIVE_NOT_EXISTS"'
        )
        verify_output = live_session.run_command(verify_cmd)

        # Check if archive was actually created
        archive_exists = False
        for line in verify_output.split("\n"):
            line = line.strip()
            if line == "ARCHIVE_EXISTS":
                archive_exists = True
                break

        if not archive_exists:
            stdout = (
                f"Failed to compress file: {file_path}\n{compress_output}\n{verify_output}"
            )
            exit_status = 1
        else:
            stdout = f"Compressed file: {file_path} into {archive_name} (using tar)\n{compress_output}"
            exit_status = 0

        return ActionExecutionResult(
            command=["tar"],
            stdout=stdout,
            exit_status=exit_status,
            session=tulpa_session_id,
            artefacts={"archive_path": archive_path, "archive_name": archive_name} if archive_exists else {},
        )

    def parse_output(self, output: ActionExecutionResult) -> dict:
        """
        Parse the output of the CompressFile action.
        Success is determined by exit_status (0 = success, 1 = failure).
        """
        success = output.exit_status == 0
        compressed_files = []

        # Extract file path from success message if present
        for line in output.stdout.split("\n"):
            line = line.strip()
            if line.startswith("Compressed file:") and "(using" in line:
                # Extract path from "Compressed file: /path/to/file into archive.tar.gz (using tar)"
                parts = line.split("Compressed file:")
                if len(parts) > 1:
                    file_part = parts[1].split("into")[0].strip()
                    if file_part:
                        compressed_files.append(file_part)

        return {
            "compressed": success,
            "success": success,
            "compressed_files": compressed_files,
            "archive_path": output.artefacts.get("archive_path", ""),
            "archive_name": output.artefacts.get("archive_name", ""),
        }

    def populate_output_motif(
        self, pattern: Pattern, discovered_data: dict
    ) -> StateChangeSequence:
        """
        Populate the output motif for CompressFile.

        Creates a File entity for the compressed archive if compression succeeded.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        # If file was successfully compressed, create archive entity
        if discovered_data.get("success"):
            archive_name = discovered_data.get("archive_name", "")
            if archive_name:
                # Create File entity for the compressed archive
                archive_change = self.output_motif.instantiate(
                    template_name="compressed_archive",
                    match_on_override=pattern.get('asset'),
                    filename=archive_name,
                    dirname="/tmp",
                    active=True,
                    compressed=True,
                )
                changes.append(archive_change)

        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Capture state changes from CompressFile execution.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
