from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif


class SendFileBase(Action):
    """
    Base class for file exfiltration actions.
    Provides common functionality for reading files and encoding them.
    """

    def __init__(self, action_name: str, protocol: str, technique: str = "T1041", tactic: str = "TA0010"):
        super().__init__(action_name, technique, tactic, ["quiet", "fast"])
        self.noise = 0.5
        self.impact = 0.6
        self.protocol = protocol
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for SendFile actions.
        Requires: Asset, Session (SSH/shell), and File to send.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_SendFile",
            description="Input motif for SendFile actions"
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
            template_name="existing_file",
            entity=Entity('File', alias='file', active=True, compressed=True),
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for SendFile actions.
        Updates the File entity with exfiltration information.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_SendFile",
            description="Output motif for SendFile actions"
        )

        output_motif.add_template(
            template_name="exfiltrated_file",
            entity=Entity('File', alias='file'),
            expected_attributes=["exfiltrated_domain", "exfiltrated_protocol"],
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        source_asset = pattern.get('asset').get('ip_address')
        file_ent = pattern.get('file')
        filename = file_ent.get('filename') if file_ent else 'file'
        return [f"Send file {filename} from {source_asset} via {self.protocol.upper()}"]

    def get_target_query(self) -> Query:
        """
        Query for assets with active shell sessions and files to send.
        """
        query = self.input_motif.get_query()
        query.where(self.input_motif.get_template('existing_session').entity.protocol.is_in(['ssh', 'shell']))
        query.where(self.input_motif.get_template('existing_file').entity.active == True)
        query.ret_all()
        return query

    def _get_file_path(self, pattern: Pattern) -> tuple[str, str]:
        """
        Extract and construct the remote file path from the pattern.
        Returns (file_path, error_message). If error_message is not empty, file_path is invalid.
        """
        file_ent = pattern.get('file')
        if not file_ent:
            return ('', "ERROR: No file found in pattern")
        
        filename = file_ent.get('filename')
        if not filename:
            return ('', "ERROR: File entity missing filename property")
        
        dirname = file_ent.get('dirname') or ''
        
        # Construct remote file path
        if dirname and dirname != '/':
            remote_file_path = f"{dirname}/{filename}"
        else:
            remote_file_path = f"/{filename}" if dirname == '/' else filename
        
        return (remote_file_path, '')

    def _encode_file(self, live_session, file_path: str) -> tuple[str, int]:
        """
        Read and base64 encode a file.
        Returns (encoded_data, exit_status)
        """
        escaped_path = file_path.replace('"', '\\"')
        read_cmd = f"base64 -w 0 \"{escaped_path}\""
        encoded_data = live_session.run_command(read_cmd).strip()
        
        if not encoded_data:
            return "", 1
        
        return encoded_data, 0

    def _send_file(self, live_session, file_path: str) -> tuple[str, int, str]:
        """
        Protocol-specific file sending implementation.
        Must be implemented by subclasses.
        Returns (output, exit_status, target_domain)
        """
        raise NotImplementedError("Subclasses must implement _send_file method")

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Send file to remote location via protocol-specific exfiltration.
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

        file_path, error_msg = self._get_file_path(pattern)
        if error_msg:
            return ActionExecutionResult(
                command=[],
                stderr=error_msg,
                exit_status=1,
                session=tulpa_session_id,
            )
        
        file_ent = pattern.get('file')
        filename = file_ent.get('filename') if file_ent else 'file'

        # Send via protocol-specific method
        try:
            output, exit_status, target_domain = self._send_file(live_session, file_path)
        except Exception as e:
            return ActionExecutionResult(
                command=[f"send-file-{self.protocol}", file_path],
                stderr=f"ERROR: Failed to send file {file_path} via {self.protocol.upper()}: {str(e)}",
                exit_status=1,
                session=tulpa_session_id,
            )

        if exit_status != 0:
            return ActionExecutionResult(
                command=[f"send-file-{self.protocol}", file_path],
                stdout=output,
                stderr=f"ERROR: Failed to send file {file_path} via {self.protocol.upper()}. Output: {output}",
                exit_status=exit_status,
                session=tulpa_session_id,
                artefacts={"target_domain": target_domain, "protocol": self.protocol},
            )

        return ActionExecutionResult(
            command=[f"send-file-{self.protocol}", file_path],
            stdout=f"SUCCESS: Sent file {file_path} via {self.protocol.upper()}\n{output}",
            exit_status=exit_status,
            session=tulpa_session_id,
            artefacts={"target_domain": target_domain, "protocol": self.protocol},
            logs=[f"Sent file {filename} via {self.protocol.upper()} exfiltration"],
        )

    def parse_output(self, output: ActionExecutionResult) -> dict:
        """
        Parse the output of the SendFile action.
        """
        return {
            "file_sent": output.exit_status == 0,
            "method": self.protocol,
            "target_domain": output.artefacts.get("target_domain", ""),
            "protocol": output.artefacts.get("protocol", self.protocol),
        }

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate the output motif for SendFile.
        Updates the File entity with exfiltration domain and protocol.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []
        
        # If file was successfully sent, update the File entity with exfiltration info
        if discovered_data.get("file_sent"):
            file_entity = pattern.get("file")
            if file_entity:
                # Create updated file entity with exfiltration properties
                updated_file = file_entity.copy()
                updated_file.set("exfiltrated_domain", discovered_data.get("target_domain", ""))
                updated_file.set("exfiltrated_protocol", discovered_data.get("protocol", self.protocol))
                changes.append((pattern, "update", updated_file))
        
        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Capture state changes from SendFile execution.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
