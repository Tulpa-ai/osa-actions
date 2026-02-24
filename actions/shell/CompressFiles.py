import os
from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation


class CompressFiles(Action):
    """
    Compress files into a tar archive on a Linux system.
    
    This action collects files from the knowledge graph and compresses them
    into a tar.gz archive using the tar command. Linux only.
    """

    def __init__(self):
        super().__init__("CompressFiles", "T1560", "TA0010", ["quiet", "fast"])
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
            name="InputMotif_CompressFiles",
            description="Input motif for CompressFiles"
        )

        input_motif.add_template(
            template_name="existing_asset",
            entity=Entity('Asset', alias='asset'),
        )

        input_motif.add_template(
            template_name="existing_port",
            entity=Entity('OpenPort', alias='port'),
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )

        input_motif.add_template(
            template_name="existing_service",
            entity=Entity('Service', alias='service'),
            relationship_type="is_running",
            match_on="existing_port",
            invert_relationship=True,
        )

        input_motif.add_template(
            template_name="existing_session",
            entity=Entity('Session', alias='session', active=True),
            relationship_type="executes_on",
            match_on="existing_service",
        )

        input_motif.add_template(
            template_name="existing_drive",
            entity=Entity('Drive', alias='drive'),
            relationship_type="accesses",
            match_on="existing_asset",
            invert_relationship=True,
        )

        input_motif.add_template(
            template_name="existing_file",
            entity=Entity('File', alias='file', active=True),
            relationship_type="directed_path",
            match_on="existing_drive",
            pattern_alias='path_to_file',
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for CompressFiles.
        Creates a File entity for the compressed archive.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_CompressFiles",
            description="Output motif for CompressFiles"
        )

        output_motif.add_template(
            template_name="compressed_archive",
            entity=Entity('File', alias='archive'),
            expected_attributes=["artefact_id", "filename"],
            operation=StateChangeOperation.MERGE_IF_NOT_MATCH,
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        asset = pattern.get('asset').get('ip_address')
        file_ent = pattern.get('file')
        filename = file_ent.get('filename', 'file') if file_ent else 'file'
        return [f"Compress {filename} on {asset} into a tar.gz archive"]

    def get_target_query(self) -> Query:
        """
        Query for assets with active shell sessions and files to compress.
        Ensures File is on the same Asset as the Session.
        """
        query = self.input_motif.get_query()
        query.where(self.input_motif.get_template('existing_session').entity.protocol.is_in(['ssh', 'shell']))
        query.where(self.input_motif.get_template('existing_file').entity.active == True)
        # Ensure File is on the same Asset as the Session (both paths share the same Asset)
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Compress files into a tar.gz archive using tar command.
        """
        tulpa_session = pattern.get('session')
        tulpa_session_id = tulpa_session.get('id')
        live_session = sessions.get_session(tulpa_session_id)

        if live_session is None:
            return ActionExecutionResult(
                command=[],
                stderr=f"Session {tulpa_session_id} not found",
                exit_status=1,
            )

        # Get file to compress (single file for now)
        file_ent = pattern.get('file')
        if not file_ent:
            return ActionExecutionResult(
                command=[],
                stderr="No file found to compress",
                exit_status=1,
            )

        # Build file path
        filename = file_ent.get('filename')
        dirname = file_ent.get('dirname', '')
        if dirname:
            file_path = os.path.join(dirname, filename) if dirname != '/' else f"/{filename}"
        else:
            file_path = filename

        # Create archive name
        archive_name = f"compressed_{filename}_{tulpa_session_id}.tar.gz"
        archive_path = f"/tmp/{archive_name}"

        # Build tar command (escape file path for shell)
        escaped_file_path = file_path.replace('"', '\\"')
        tar_cmd = f"tar -czf {archive_path} \"{escaped_file_path}\" 2>&1"
        
        output = live_session.run_command(tar_cmd)
        
        # Check if archive was created
        check_cmd = f"test -f {archive_path} && echo 'Archive created' || echo 'Archive creation failed'"
        check_output = live_session.run_command(check_cmd)
        
        if "Archive created" not in check_output:
            return ActionExecutionResult(
                command=[tar_cmd],
                stdout=output,
                stderr="Failed to create archive",
                exit_status=1,
                session=tulpa_session_id,
            )

        # Store archive path in remote system (we'll reference it later for sending)
        # For now, just log that it was created
        return ActionExecutionResult(
            command=[tar_cmd],
            stdout=f"Compressed file {file_path} into {archive_name}\n{output}",
            exit_status=0,
            session=tulpa_session_id,
            artefacts={"archive_path": archive_path, "archive_name": archive_name},
            logs=[f"Created archive {archive_name} containing {filename}"],
        )

    def parse_output(self, output: ActionExecutionResult) -> dict:
        """
        Parse the output of the CompressFiles action.
        """
        return {
            "archive_created": output.exit_status == 0,
            "archive_path": output.artefacts.get("archive_path", ""),
            "archive_name": output.artefacts.get("archive_name", ""),
        }

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate the output motif for CompressFiles.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        if not discovered_data.get("archive_created"):
            return changes

        archive_name = discovered_data.get("archive_name", "")
        if not archive_name:
            return changes

        # Create File entity for the compressed archive
        archive_change = self.output_motif.instantiate(
            template_name="compressed_archive",
            match_on_override=pattern.get('asset'),
            filename=archive_name,
            dirname="/tmp",
            active=True,
        )
        changes.append(archive_change)

        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Capture state changes from CompressFiles execution.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
