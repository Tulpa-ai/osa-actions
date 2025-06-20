"""Tests for `ImportNessusScanResultsFromCSV` action."""

import sys
import os

# Add the parent directory to the path to find the action module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ImportNessusScanResultsFromCSV import ImportNessusScanResultsFromCSV

def test_ImportNessusScanResultsFromCSV():
    """Test ImportNessusScanResultsFromCSV action."""
    action = ImportNessusScanResultsFromCSV()
    assert action.tactic == "TA0043 Reconnaissance"
    assert action.technique == "T1595 Active Scanning"
    assert action.name == "ImportNessusScanResultsFromCSV"
    assert action.noise == 0.0
    assert action.impact == 0.0
    assert action.tags == []