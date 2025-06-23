import os
import pathlib
import pandas as pd

from action_state_interface.action import Action, StateChangeSequence
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
        query.match(Entity('NessusScanResultFile', alias='nessus_file_location'))
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern):
        """Execute the action."""
        # Read the location of the file from a property on the entity
        file_location = pattern.get('nessus_file_location').get('file_location')
        if not os.path.exists(file_location):
            raise FileNotFoundError(f"File {file_location} not found")
        
        # Read the file and parse into pandas DataFrame
        try:
            df = pd.read_csv(file_location)
            return ActionExecutionResult(
                command=["pd.read_csv", file_location],
                stdout=f"Successfully parsed CSV file with {len(df)} rows and {len(df.columns)} columns",
                data={"dataframe": df}
            )
        except Exception as e:
            return ActionExecutionResult(
                command=["pd.read_csv", file_location],
                exit_status=1,
                stderr=f"Error parsing CSV file: {str(e)}"
            )
        
    
    def capture_state_change(self, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult):
        """Capture the state change."""
        changes: StateChangeSequence = []
        nessus_plugins = {
            "10287": {
                "target_entity_type": "Asset",
                "property_type_to_col_names":
                  {
                     "ip_address": "Host" 
                  }  
            }
        }
        df = output.data.get('dataframe')
        df['Plugin ID'] = df['Plugin ID'].astype('string')
        for plugin in nessus_plugins:
            if plugin in df['Plugin ID'].values:
                print("Plugin found: ", plugin)
                target_entity_type = nessus_plugins[plugin]["target_entity_type"]
                property_type_to_col_names = nessus_plugins[plugin]["property_type_to_col_names"]
                
                needed_columns = list(property_type_to_col_names.values())
                needed_columns.append('Plugin ID')  # Keep Plugin ID for filtering
                plugin_df = df[df['Plugin ID'] == plugin][needed_columns]
                
                for row in plugin_df.to_dict(orient='records'):
                    row_properties = {}
                    for property_type, col_name in property_type_to_col_names.items():
                        print("row: ", row)
                        print("col_name: ", col_name)
                        print("property_type: ", property_type)
                        print("property_type_to_col_names: ", property_type_to_col_names)
                        print("row[col_name]: ", row[col_name])
                        row_properties[property_type] = row[col_name]
                    changes.append(
                        Entity(target_entity_type, alias=target_entity_type.lower(), **row_properties)
                    )
                print("CHANGES")
                print(changes)

        # asset = Entity('Asset', alias='asset', ip_address=ip)
        #     sub_asset_pattern = asset.with_edge(Relationship('belongs_to')).with_node(subnet)
        #     changes.append((subnet, "merge", sub_asset_pattern))
        return changes