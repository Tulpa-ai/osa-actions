import pathlib

from action_state_interface.action import Action
from artefacts.ArtefactManager import ArtefactManager
from Session import SessionManager
from kg_api import Pattern
from action_state_interface.exec import ActionExecutionResult

class ImportNessusScanResultsFromCSV(Action):
    """Import Nessus scan results from a CSV file."""

    def __init__(self):
        super().__init__("ImportNessusScanResultsFromCSV", "T1595 Active Scanning", "TA0043 Reconnaissance", [])
        self.noise = 0.0
        self.impact = 0.0

    def get_target_query(self):
        """Get the target query for the action."""
        pass
    
    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern):
        """Execute the action."""
        pass
    
    def capture_state_change(self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult):
        """Capture the state change."""
        pass