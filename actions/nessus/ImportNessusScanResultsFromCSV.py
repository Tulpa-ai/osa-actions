import pathlib

from action_state_interface.action import Action
from artefacts.ArtefactManager import ArtefactManager
from Session import SessionManager
from kg_api import Entity, Pattern, Relationship
from action_state_interface.exec import ActionExecutionResult
from kg_api.query import Query

class ImportNessusScanResultsFromCSV(Action):
    """Import Nessus scan results from a CSV file."""

    def __init__(self):
        super().__init__("ImportNessusScanResultsFromCSV", "T1595 Active Scanning", "TA0043 Reconnaissance", [])
        self.noise = 0.0
        self.impact = 0.0

    def get_target_query(self):
        """Get the target query for the action."""
        query = Query()
        #Maybe throw in here a check to see if the Entity has the right file location Property before allowing the action?
        query.match(Entity('NessusScanResultFile', alias='nessus_scan_result_file'))
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern):
        """Execute the action."""
        # Read the location of the file from a property on the entity
        # Read the file
        # Parse the file
        # Return the parsed data
        pass
    
    def capture_state_change(self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult):
        """Capture the state change."""
        pass