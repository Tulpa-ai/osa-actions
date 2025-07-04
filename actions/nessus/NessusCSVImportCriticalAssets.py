from ast import literal_eval
import os
import pathlib
import pandas as pd
from ipaddress import ip_address
import json

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
        
        
    
    def capture_state_change(self, gdb: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult):
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
        df_artefact_id = output.artefacts.get('downloaded_file_id')
        df = pd.read_csv(artefacts.get_path(df_artefact_id))
        grouped = df.groupby(['Host', 'Port', 'Protocol'])

        def create_vulnerabilities_list(df_group):
            vulns = []
            for _, row in df_group.iterrows():
                provenance = 'Nessus'
                risk_level = str(row['Risk'])
                vuln_detail = str(row['Name'])
                vulns.append((provenance, risk_level, vuln_detail))
            return vulns

        for (host, port, protocol), group in grouped:
            
            vulns_detail = create_vulnerabilities_list(group)            
            
            current_asset = Entity('Asset', alias='asset', ip_address=host)

            #TODO: move this out one level in the loop so that we're not doing so many lookups
            existing_asset_match = gdb.get_matching(current_asset)

            if existing_asset_match:
                print(f"ASSET MATCH {existing_asset_match}")
                current_asset = existing_asset_match[0].get('asset')
            else:
                print(f"NO ASSET MATCH {existing_asset_match}")
                current_asset = Entity('Asset', alias='asset', ip_address=host)
                changes.append((None, 'merge', current_asset))
    
            existing_asset_and_port_pattern = current_asset.with_edge(Relationship('has')).with_node(
                Entity('OpenPort', alias='port', number=int(port), protocol=protocol)
            )

            existing_port_match = gdb.get_matching(existing_asset_and_port_pattern)

            if existing_port_match:
                print(f"PORT MATCH {existing_port_match}")
                current_port = existing_port_match[0].get('port')
            else:                
                print(f"NO PORT MATCH {existing_port_match}")                    
                changes.append((current_asset, 'merge', existing_asset_and_port_pattern))
                current_port = existing_asset_and_port_pattern.get('port')
            
            #TODO: Remove this janky string manipulation
            existing_vuln_list = current_port.get('vulnerabilities')
            if existing_vuln_list:
                print(f"EXISTING VULN LIST, current_port = {current_port}")
                parsed_existing_vulns_list = literal_eval(existing_vuln_list)
                for new_vuln in vulns_detail:
                    if new_vuln not in parsed_existing_vulns_list:
                        parsed_existing_vulns_list.append(new_vuln)
                current_port.set('vulnerabilities', str(parsed_existing_vulns_list))
            else:
                print(f"NO EXISTING VULN LIST, current_port = {current_port}")
                current_port.set('vulnerabilities', str(vulns_detail))

            change = (existing_asset_and_port_pattern, 'update', current_port)
            print(f"change = {change}")

            changes.append(change)
        print("\nCHANGES\n")
        print("\nCHANGES\n")
        print("\nCHANGES\n")
        for change in changes:
            print(change)
        print("\nCHANGES\n")
        print("\nCHANGES\n")
        print("\nCHANGES\n")
        return changes