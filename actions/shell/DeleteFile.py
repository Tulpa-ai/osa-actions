import os

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
    
    This action deletes files on Linux systems.
    Supports secure deletion (shred, wipe, srm) with fallback to regular deletion (rm).
    """
    
    # Shell-capable protocols for running commands
    SHELL_PROTOCOLS = ['ssh', 'shell', 'busybox']
    
    # Secure deletion tools to try in order
    SECURE_DELETION_TOOLS = [
        ('shred', 'shred -fuz "{path}"'),
        ('wipe', 'wipe -f "{path}"'),
        ('srm', 'srm "{path}"')
    ]

    def __init__(self):
        super().__init__(
            "DeleteFile", "T1561.001", "TA0040", ["loud", "fast"]
        )
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
            name="InputMotif_DeleteFile",
            description="Input motif for DeleteFile"
        )

        # Asset (required for session and file location)
        input_motif.add_template(
            entity=Entity('Asset', alias='asset'),
            template_name="existing_asset",
        )

        # Drive entity (ensures file is on the same asset)
        input_motif.add_template(
            entity=Entity('Drive', alias='drive'),
            template_name="existing_drive",
            relationship_type="directed_path",
            match_on="existing_asset",
        )

        # Directory entity (required for file path construction)
        input_motif.add_template(
            entity=Entity('Directory', alias='directory'),
            template_name="existing_directory",
            relationship_type="directed_path",
            match_on="existing_drive",
        )

        # File entity to delete
        input_motif.add_template(
            entity=Entity('File', alias='file'),
            template_name="existing_file",
            relationship_type="directed_path",
            match_on="existing_directory",
        )

        # Session from any service on the asset
        input_motif.add_template(
            entity=Entity('OpenPort', alias='session_port'),
            template_name="existing_session_port",
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity('Service', alias='session_service'),
            template_name="existing_session_service",
            relationship_type="is_running",
            match_on="existing_session_port",
            invert_relationship=True,
        )

        # Session executing on the service
        input_motif.add_template(
            entity=Entity('Session', alias='session', active=True),
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
            name="OutputMotif_DeleteFile",
            description="Output motif for DeleteFile"
        )

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        asset = pattern.get('asset')
        asset_ip = asset.get('ip_address') if asset else 'unknown'
        file_entity = pattern.get('file')
        filename = file_entity.get('filename') if file_entity else 'unknown'
        session = pattern.get('session')._id
        session_service = pattern.get('session_service')
        session_service_protocol = session_service.get('protocol') if session_service else 'unknown'
        
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
            self.input_motif.get_template('existing_session_service').entity.protocol.is_in(
                self.SHELL_PROTOCOLS
            )
        )
        # Ensure session is shell-capable
        query.where(
            self.input_motif.get_template('existing_session').entity.protocol.is_in(
                self.SHELL_PROTOCOLS
            )
        )
        # Only show action for active files (exclude files where active is False)
        file_template = self.input_motif.get_template('existing_file')
        query.where_not(file_template.entity.active == False)
        query.ret_all()
        return query

    def _get_file_path(self, pattern: Pattern) -> str:
        """
        Construct the full file path from the File entity and its relationships.
        Returns the file path or just the filename if path cannot be determined.
        """
        file_entity = pattern.get('file')
        if not file_entity:
            return ""
        
        filename = file_entity.get('filename')
        if not filename:
            return ""
        
        # Use absolute directory path from File entity if available
        dirname_ab = file_entity.get('dirname_ab')
        if dirname_ab:
            return os.path.join(dirname_ab, filename)
        
        # Fallback: try to get directory path from Directory entity
        directory = pattern.get('directory')
        if directory:
            dirname = directory.get('dirname')
            if dirname:
                return os.path.join(dirname, filename)
        
        # Fallback: return just filename (will need to be found)
        return filename

    def _escape_path_for_shell(self, file_path: str) -> str:
        """
        Escape a file path for safe use in shell commands within double quotes.
        Escapes backslashes and double quotes.
        """
        return file_path.replace('\\', '\\\\').replace('"', '\\"')

    def _try_secure_deletion(self, live_session, file_path: str) -> tuple[str, bool]:
        """
        Try secure deletion methods (shred, wipe, srm) in order.
        Returns (command_output, success).
        """
        # Escape file_path for safe use in shell commands
        escaped_path = self._escape_path_for_shell(file_path)
        for tool_name, tool_cmd in self.SECURE_DELETION_TOOLS:
            # Use escaped path in the tool command
            cmd = f'which {tool_name} >/dev/null 2>&1 && {tool_cmd.format(path=escaped_path)} 2>/dev/null && echo "Deleted file: {escaped_path} (using {tool_name})" || true'
            output = live_session.run_command(cmd)
            # Check for actual success message (not just the command being echoed)
            # Success message should be a standalone line starting with "Deleted file:"
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('Deleted file:') and '(using' in line:
                    return output, True
        
        return "", False

    def _regular_deletion(self, live_session, file_path: str) -> str:
        """
        Perform regular deletion using rm.
        """
        # Escape file_path for safe use in shell commands
        escaped_path = self._escape_path_for_shell(file_path)
        rm_cmd = f'rm -f "{escaped_path}" 2>/dev/null && echo "Deleted file: {escaped_path} (using rm)" || echo "Failed to delete: {escaped_path}"'
        return live_session.run_command(rm_cmd)

    def _create_error_result(self, message: str, session_id: str) -> ActionExecutionResult:
        """
        Create an error ActionExecutionResult.
        """
        return ActionExecutionResult(
            command=[],
            stdout=message,
            exit_status=1,
            session=session_id
        )

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Execute file deletion commands.
        
        Deletes files by:
        1. Getting the file path from the File entity
        2. Trying secure deletion methods first (shred, wipe, srm)
        3. Falling back to regular deletion (rm) if secure methods unavailable
        """
        tulpa_session = pattern.get('session')
        tulpa_session_id = tulpa_session.get('id')
        live_session = sessions.get_session(tulpa_session_id)
        
        if not live_session:
            return self._create_error_result("No active session available", tulpa_session_id)
        
        file_path = self._get_file_path(pattern)
        
        if not file_path:
            return self._create_error_result("No file path found", tulpa_session_id)
        
        commands_executed = []
        output_lines = []
        
        # Try secure deletion first
        secure_output, success = self._try_secure_deletion(live_session, file_path)
        
        if success:
            output_lines.append(secure_output)
            commands_executed.append("secure_deletion")
        else:
            # Fallback to regular deletion
            regular_output = self._regular_deletion(live_session, file_path)
            output_lines.append(regular_output)
            commands_executed.append("regular_deletion")
        
        stdout = "\n".join(output_lines) if output_lines else "No file deleted"
        # Check for actual success message (line starting with "Deleted file:")
        success = False
        for line in output_lines:
            line_stripped = line.strip()
            if line_stripped.startswith('Deleted file:') and '(using' in line_stripped:
                success = True
                break
        exit_status = 0 if success else 1
        
        return ActionExecutionResult(
            command=commands_executed,
            stdout=stdout,
            exit_status=exit_status,
            session=tulpa_session_id
        )

    def parse_output(self, output: ActionExecutionResult) -> dict:
        """
        Parse the output of the DeleteFile action.
        Extracts which files were deleted from the command output.
        """
        deleted_files = []
        deleted = False
        lines = output.stdout.split("\n")
        
        for line in lines:
            line_stripped = line.strip()
            # Only match actual success messages (standalone lines starting with "Deleted file:")
            # This avoids matching the command itself which might be echoed in output
            if line_stripped.startswith('Deleted file:') and '(using' in line_stripped:
                # Format: "Deleted file: /path/to/file (using method)"
                parts = line_stripped.split("Deleted file:")
                if len(parts) > 1:
                    file_part = parts[1].split("(using")[0].strip()
                    if file_part:
                        deleted_files.append(file_part)
                        deleted = True
        
        return {
            "deleted": deleted,
            "success": output.exit_status == 0 and deleted,
            "deleted_files": deleted_files
        }

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate the output motif for DeleteFile.
        
        Updates the File entity to mark it as inactive (active: False) after deletion.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []
        
        # If file was successfully deleted, mark it as inactive
        if discovered_data.get("success"):
            file_entity = pattern.get('file')
            if file_entity:
                # Create updated file entity with active: False
                updated_file = file_entity.copy()
                updated_file.set('active', False)
                changes.append((pattern, "update", updated_file))
        
        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Capture state changes from file deletion.
        
        Marks the deleted File entity as inactive (active: False) in the graph.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
