import re

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation


class StopService(Action):
    """
    Stop a system service.
    """

    def __init__(self):
        super().__init__("StopService", "T1569", "TA0002", ["quiet", "fast"])
        self.noise = 0.3
        self.impact = 0.2
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        input_motif = ActionInputMotif(
            name="InputMotif_StopService",
            description="Input motif for StopService"
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
            entity=Entity('Service', alias='service'),
            template_name="existing_service",
            relationship_type="is_running",
            match_on="existing_port",
            invert_relationship=True,
        )
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
        input_motif.add_template(
            entity=Entity('Session', alias='session', active=True),
            template_name="existing_session",
            relationship_type="executes_on",
            match_on="existing_session_service",
        )
        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        output_motif = ActionOutputMotif(
            name="OutputMotif_StopService",
            description="Output motif for StopService"
        )
        output_motif.add_template(
            entity=Entity('Service', alias='service'),
            template_name="updated_service",
            operation=StateChangeOperation.UPDATE,
        )
        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        service = pattern.get('service')
        port = pattern.get('port')
        asset = pattern.get('asset')
        
        service_name = service.get('name') or service.get('protocol') or 'service'
        port_number = port.get('number') if port else None
        ip_address = asset.get('ip_address') if asset else None
        
        parts = [f"Stop service {service_name}"]
        if port_number:
            parts.append(f"on port {port_number}")
        if ip_address:
            parts.append(f"and asset {ip_address}")
        
        return [" ".join(parts)]

    def get_target_query(self) -> Query:
        query = self.input_motif.get_query()
        query.where(
            self.input_motif.get_template('existing_session').entity.protocol.is_in(['ssh', 'shell', 'busybox'])
        )
        query.ret_all()
        return query

    def function(
        self,
        sessions: SessionManager,
        artefacts: ArtefactManager,
        pattern: Pattern,
    ) -> ActionExecutionResult:
        tulpa_session = pattern.get('session')
        tulpa_session_id = tulpa_session.get('id')
        live_session = sessions.get_session(tulpa_session_id)

        if not live_session:
            return ActionExecutionResult(
                command=[],
                stdout="No active session available",
                exit_status=1,
                session=tulpa_session_id,
            )

        port = pattern.get('port')
        port_number = port.get('number') if port else None
        
        if not port_number:
            return ActionExecutionResult(
                command=[],
                stdout="Port number not found",
                exit_status=1,
                session=tulpa_session_id,
            )

        ss_cmd = f"ss -tlnp 2>&1 | grep ':{port_number} ' | head -1"
        ss_output = live_session.run_command(ss_cmd)
        pid_match = re.search(r'pid=(\d+)', ss_output)
        
        if not pid_match:
            return ActionExecutionResult(
                command=[ss_cmd],
                stdout=f"Could not find process on port {port_number}",
                exit_status=1,
                session=tulpa_session_id,
            )
        
        pid = pid_match.group(1)
        kill_cmd = f"kill -KILL {pid}"
        live_session.run_command(kill_cmd)
        
        exit_status = 0
        stdout = f"Killed process {pid} on port {port_number}"
        
        return ActionExecutionResult(
            command=[ss_cmd, kill_cmd],
            stdout=stdout,
            exit_status=exit_status,
            session=tulpa_session_id,
        )

    def parse_output(self, output: ActionExecutionResult) -> dict:
        return {
            "success": output.exit_status == 0,
        }

    def populate_output_motif(
        self, pattern: Pattern, discovered_data: dict
    ) -> StateChangeSequence:
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        if discovered_data.get("success"):
            service = pattern.get('service')
            
            changes.append(
                self.output_motif.instantiate(
                    template_name="updated_service",
                    match_on_override=service,
                    active=False,
                )
            )

        return changes

    def capture_state_change(
        self,
        artefacts: ArtefactManager,
        pattern: Pattern,
        output: ActionExecutionResult,
    ) -> StateChangeSequence:
        discovered_data = self.parse_output(output)
        return self.populate_output_motif(pattern, discovered_data)
