import os
import pathlib
import pandas as pd
from ipaddress import ip_address

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import get_attack_ips, get_non_attack_ips
from artefacts.ArtefactManager import ArtefactManager
from Session import SessionManager
from kg_api import Entity, Pattern, Relationship, GraphDB
from action_state_interface.exec import ActionExecutionResult
from kg_api.query import Query

base_path = pathlib.Path(__file__).parent.parent.parent

class NessusCSVImportCriticalAssets(Action):
    """Import Nessus scan results from a CSV file, filtering for Critical risk vulnerabilities only."""

    def __init__(self):
        super().__init__("NessusCSVImportCriticalAssets", "T1595 Active Scanning", "TA0043 Reconnaissance", [])
        self.noise = 0.1
        self.impact = 0

    def get_target_query(self):
        """Get the target query for the action."""
        #Maybe throw in here a check to see if the Entity has the right file location Property before allowing the action?
        nessus_file_entity = Entity('NessusScanResultFile', alias='nessus_file_location')
        query = Query()
        query.match(nessus_file_entity)
        query.ret_all()
        return query

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        return [f"Extract knowledge of critical vulnerabilities from {pattern.get('nessus_file_location').get('file_location')}"]

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern):
        """Execute the action."""
        # Read the location of the file from a property on the entity
        file_location = pattern.get('nessus_file_location').get('file_location')
        if not os.path.exists(file_location):
            raise FileNotFoundError(f"File {file_location} not found")
        
        try:
            df = pd.read_csv(file_location)
        except Exception as e:
            return ActionExecutionResult(
                command=[f"pd.read_csv('{file_location}')"],
                exit_status=1,
                stderr=f"Error parsing CSV file: {str(e)}"
            )
        
        # Filter for Critical risk vulnerabilities only
        if 'Risk' in df.columns:
            df = df[df['Risk'] == 'Critical']
        
        # Filter IPs using the same pattern as FastNmapScan
        NON_ATTACK_IPS = get_non_attack_ips(base_path / 'non_attack_ips.txt')
        ATTACK_IPS = get_attack_ips(base_path / 'attack_ips.txt')
        
        # Convert to sets for efficient lookup
        non_attack_ips_set = set(NON_ATTACK_IPS)
        attack_ips_set = set(ATTACK_IPS)
        
        # Filter out non-targetable IPs efficiently
        if 'Host' in df.columns:
            # Convert to IPv4 addresses and filter
            ip4_non_attack_ips = {ip for ip in NON_ATTACK_IPS if ip_address(ip).version == 4}
            ip4_attack_ips = {ip for ip in ATTACK_IPS if ip_address(ip).version == 4}
            
            # Filter dataframe to only include targetable IPs
            if ATTACK_IPS:
                # If attack IPs are specified, only include those
                df = df[df['Host'].isin(ip4_attack_ips)]
            elif NON_ATTACK_IPS:
                # Otherwise, exclude non-attack IPs
                df = df[~df['Host'].isin(ip4_non_attack_ips)]# If no attack or non-attack IPs are specified, do nothing                
        
        try:
            uuid = artefacts.placeholder(file_location)
            artefact_path = artefacts.get_path(uuid)
            df.to_csv(artefact_path, index=False)
            return ActionExecutionResult(
                command=[f"pd.read_csv('{file_location}')"],
                stdout=f"Successfully parsed CSV file with {len(df)} rows and {len(df.columns)} columns after Critical risk and IP filtering",
                artefacts={"downloaded_file_id": uuid}
            )
        except Exception as e:
            return ActionExecutionResult(
                command=[f"pd.read_csv({file_location})"],
                exit_status=1,
                stderr=f"Error saving dataframe to artefact manager: {str(e)}"
            )
        
        
    
    def capture_state_change(self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult):
        """
        Captures the state change in the knowledge graph after the Nessus scan results are imported.

        Args:
            kg (GraphDB): The knowledge graph representing the current state of the system.
            artefacts (ArtefactManager): Manages artefacts related to the Nessus scan results.
            pattern (Pattern): The pattern describing the Nessus scan results file.
            output (ActionExecutionResult): The result of the Nessus scan results import.

        Returns:
            StateChangeSequence: A sequence of changes made to the system state.
        """        
         
        changes: StateChangeSequence = []
        nessus_plugins = {
            "all": {  # We'll process all plugins now, not just specific ones
                "target_entity_type": "Asset",
                "property_type_to_col_names": {
                    "ip_address": "Host",
                    "Nessus_risk": "Risk",
                    "Nessus_port_and_vulnerability": None  # We'll compute this
                }
            }
        }
        df_artefact_id = output.artefacts.get('downloaded_file_id')
        df = pd.read_csv(artefacts.get_path(df_artefact_id))

        # Group by Host and create vulnerabilities dictionary
        def create_vulnerabilities_dict(df_group):
            vulnerabilities = {}
            for _, row in df_group.iterrows():
                port = str(row['Port'])
                name = str(row['Name'])
                if port not in vulnerabilities:
                    vulnerabilities[port] = []
                if name not in vulnerabilities[port]:
                    vulnerabilities[port].append(name)
            return vulnerabilities

        # Group by Host and process each group
        grouped = df.groupby('Host')
        
        for host, group in grouped:
            # Create properties dictionary for the entity
            properties = {
                "ip_address": host,
                "Nessus_risk": group['Risk'].iloc[0],
                "Nessus_port_and_vulnerability": create_vulnerabilities_dict(group)
            }
            
            # Create the new entity with the correct alias format
            new_entity = Entity("Asset", alias="asset", **properties)
            
            # Add to changes sequence
            changes.append((None, "merge", new_entity))

        return changes 