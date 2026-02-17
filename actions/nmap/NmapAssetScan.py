import xml.etree.ElementTree as ET

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import parse_nmap_xml_report, shell, query_scap_for_cve_fuzzy
from action_state_interface.exec import ActionExecutionError, ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, Pattern
from kg_api.query import Query
from Session import SessionManager
from motifs import ActionInputMotif, ActionOutputMotif

# Helper function for OS scan parsing
def nmap_parse_os_version_and_family(xml_str):
    """
    Parse the OS version and family from the nmap XML output.
    """
    root = ET.fromstring(xml_str)
    os_version = "unknown"
    os_family = "unknown"
    os_cpe = "unknown"

    # The previous := check here wasn't safe because Element objects are considered False if they have no children
    osmatch = root.find(".//osmatch")
    if osmatch is not None:
        os_version = osmatch.get("name", "unknown")
        osclass = osmatch.find(".//osclass")
        if osclass is not None:
            os_family = osclass.get("osfamily", "unknown")
        cpe = osmatch.find(".//cpe")
        if cpe is not None:
            os_cpe = cpe.text

    return os_version, os_family, os_cpe

def ftp_nmap_parser(port_data: dict, parsed_info: dict, conn=None) -> dict:
    """
    Parse FTP-specific information and return structured data for motif instantiation.

    Args:
        port_data: Port information dictionary
        parsed_info: Full parsed nmap information
        conn: Database connection for CVE queries

    Returns:
        Dictionary containing service data and additional entities to create
    """
    anon_login = parsed_info["ftp_anon_login"]
    users = parsed_info["ftp_users"]

    service_data = {
        "protocol": port_data["service_name"],
        "version": f"{port_data['product']} {port_data['version']}".strip(),
        "cpe": port_data["cpe"],
        "anonymous_login": anon_login
    }

    # Get service-level vulnerabilities
    service_vulnerabilities = []
    if port_data["cpe"] and port_data["cpe"] != "unknown":
        cve_dict = query_scap_for_cve_fuzzy(port_data["cpe"], conn)
        for cve_id, details in cve_dict.items():
            service_vulnerabilities.append({
                "id": cve_id,
                "source": details[0],
                "criteria": details[1]
            })

    # Prepare user entities data
    user_entities = []
    for username in users:
        user_entities.append({
            "username": username,
            "relationship_to_service": "is_client"
        })

    return {
        "service_data": service_data,
        "service_vulnerabilities": service_vulnerabilities,
        "user_entities": user_entities
    }

def generic_service_parser(port_data: dict, parsed_info: dict, conn=None) -> dict:
    """
    Parse generic service information and return structured data for motif instantiation.

    Args:
        port_data: Port information dictionary
        parsed_info: Full parsed nmap information
        conn: Database connection for CVE queries

    Returns:
        Dictionary containing service data and vulnerabilities
    """
    service_data = {
        "protocol": port_data["service_name"],
        "version": f"{port_data['product']} {port_data['version']}".strip(),
        "cpe": port_data["cpe"]
    }

    # Get service-level vulnerabilities
    service_vulnerabilities = []
    if port_data["cpe"] and port_data["cpe"] != "unknown":
        cve_dict = query_scap_for_cve_fuzzy(port_data["cpe"], conn)
        for cve_id, details in cve_dict.items():
            service_vulnerabilities.append({
                "id": cve_id,
                "source": details[0],
                "criteria": details[1]
            })

    return {
        "service_data": service_data,
        "service_vulnerabilities": service_vulnerabilities,
        "user_entities": []  # No user entities for generic services
    }


class NmapAssetScan(Action):
    def __init__(self):
        super().__init__("NmapAssetScan", "T1046", "TA0007", ["loud", "fast"])
        self.noise = 0.9
        self.impact = 0
        self._parsers = {'ftp': ftp_nmap_parser}
        self.input_motif = self.build_input_motif()
        self.output_motif = self.build_output_motif()

    @classmethod
    def build_input_motif(cls) -> ActionInputMotif:
        """
        Build the input motif for NmapAssetScan.

        Defines the required asset entity that must exist for the scan to be applicable.

        Returns:
            ActionInputMotif: Input motif requiring a Asset entity
        """
        input_motif = ActionInputMotif(
            name="InputMotif_NmapAssetScan",
            description="Input requirements for NMAP asset scan on asset",
        )
        input_motif.add_template(
            entity=Entity('Asset', alias='asset'),
            template_name="asset",
            expected_attributes=["ip_address"]
        )
        return input_motif

    @classmethod
    def build_output_motif(cls) -> ActionOutputMotif:
        """
        Build the output motif templates for NmapAssetScan.

        Defines templates for:
        - Open ports (linked to assets via has relationship)
        - Services (linked to ports via is_running relationship)
        - Asset vulnerabilities (linked to assets via exposes relationship)
        - Service vulnerabilities (linked to services via exposes relationship)
        - Users (linked to services via is_client relationship)

        Returns:
            ActionOutputMotif: Output motif with port, service, vulnerability, and user templates
        """
        asset = Entity('Asset', alias='asset')
        output_motif = ActionOutputMotif(
            name="NmapAssetScan_output",
            description="Templates for discovered ports, services, vulnerabilities, and users (0-N instances each)"
        )
        output_motif.add_template(
            entity=Entity('OpenPort', alias='port'),
            template_name="discovered_port",
            match_on=asset,
            relationship_type='has',
            invert_relationship=True
        )
        output_motif.add_template(
            entity=Entity('Service', alias='service'),
            template_name="discovered_service",
            match_on="discovered_port",
            relationship_type='is_running',
            invert_relationship=True
        )
        output_motif.add_template(
            entity=Entity('Vulnerability', alias='vuln'),
            template_name="asset_vulnerability",
            match_on=asset,
            relationship_type='exposes',
            invert_relationship=True
        )
        output_motif.add_template(
            entity=Entity('Vulnerability', alias='vuln'),
            template_name="service_vulnerability",
            match_on="discovered_service",
            relationship_type='exposes',
            invert_relationship=True
        )
        output_motif.add_template(
            entity=Entity('User', alias='user'),
            template_name="discovered_user",
            match_on="discovered_service",
            relationship_type='is_client',
            invert_relationship=False
        )
        return output_motif

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        return [
            f"Gain knowledge of network services on {pattern.get('asset').get('ip_address')}. May include additional details for some services, such as indicating if anonymous FTP is supported.",
        ]

    def get_target_query(self) -> Query:
        """
        Get target query using input motif to find valid Asset entities for scanning.
        """
        query = self.input_motif.get_query()
        query.ret_all()
        return query

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        asset = pattern.get('asset')
        uuid = artefacts.placeholder("nmap-asset-scan.xml")
        out_path = artefacts.get_path(uuid)
        result = shell("nmap", ["-n", "-T4", "-Pn", "-sT", "-sV", "--version-light", "-O", "-p-", "--max-retries", "1", asset.get('ip_address'), "-oX", out_path])
        result.artefacts["xml_report"] = uuid
        return result

    def parse_output(self, artefacts: ArtefactManager, output: ActionExecutionResult, conn=None) -> dict:
        """
        Parse the nmap XML output and extract all relevant information for motif-based approach.

        This method performs the following steps:
        1. Opens and reads the XML report file from the artefacts
        2. Parses OS information (version, family, CPE) from the XML
        3. Parses port and service information from the XML
        4. Extracts open ports and their associated service details
        5. Queries CVE database for asset-level vulnerabilities based on OS CPE
        6. Processes each service using appropriate service-specific parsers
        7. Returns structured data dictionary ready for motif instantiation

        Args:
            artefacts: ArtefactManager for accessing files
            output: ActionExecutionResult containing the nmap scan results
            conn: Database connection for CVE queries

        Returns:
            Dictionary containing parsed nmap data including OS info, ports, services,
            vulnerabilities, and user entities ready for motif instantiation
        """
        try:
            with artefacts.open(output.artefacts["xml_report"], 'r') as f:
                content = f.read()
        except KeyError as e:
            raise ActionExecutionError(e)

        try:
            os_version, os_family, os_cpe = nmap_parse_os_version_and_family(content)
        except ET.ParseError as e:
            raise ActionExecutionError(e)

        # Parse port and service information
        parsed_info = parse_nmap_xml_report(content)

        # Extract open ports and their services
        open_ports = []
        for port in parsed_info["ports"]:
            if port["state"] != "open":
                continue

            port_data = {
                "portid": port["portid"],
                "protocol": port["protocol"],
                "service_name": port["service"].get("name", ""),
                "product": port["service"].get("product", ""),
                "version": port["service"].get("version", ""),
                "cpe": port.get("cpe", "unknown")
            }
            open_ports.append(port_data)

        # Get asset-level vulnerabilities from OS CPE
        asset_vulnerabilities = []
        if os_cpe != "unknown":
            cve_dict = query_scap_for_cve_fuzzy(os_cpe, conn)
            for cve_id, details in cve_dict.items():
                asset_vulnerabilities.append({
                    "id": cve_id,
                    "source": details[0],
                    "criteria": details[1]
                })

        # Process each port with service-specific parsing
        processed_ports = []
        for port_data in open_ports:
            # Use service-specific parser if available, otherwise use generic
            if port_data["service_name"] in self._parsers:
                if port_data["service_name"] == "ftp":
                    service_info = ftp_nmap_parser(port_data, parsed_info, conn)
                else:
                    service_info = generic_service_parser(port_data, parsed_info, conn)
            else:
                service_info = generic_service_parser(port_data, parsed_info, conn)

            processed_ports.append({
                "port_data": port_data,
                "service_info": service_info
            })

        return {
            "os_version": os_version,
            "os_family": os_family,
            "os_cpe": os_cpe,
            "asset_vulnerabilities": asset_vulnerabilities,
            "processed_ports": processed_ports
        }

    def populate_output_motif(self, pattern: Pattern, discovered_data: dict, conn=None) -> StateChangeSequence:
        """
        Create state changes from parsed nmap data using the new parsing approach and motif templates.

        This method:
        1. Resets the output motif context for this execution
        2. Updates the asset with OS information
        3. Instantiates asset-level vulnerability templates
        4. Instantiates port templates for each open port
        5. Instantiates service templates with service-specific data
        6. Instantiates service-level vulnerability templates
        7. Instantiates user templates for service-specific users (e.g., FTP users)
        8. Returns all state changes

        Args:
            pattern: Input pattern containing the asset
            discovered_data: Dictionary containing parsed nmap data from parse_output
            conn: Database connection for CVE queries

        Returns:
            StateChangeSequence containing all state changes
        """
        self.output_motif.reset_context()
        asset = pattern.get('asset')
        changes: StateChangeSequence = []

        # Update asset with OS information
        asset.set('os_version', discovered_data["os_version"])
        asset.set('os_family', discovered_data["os_family"])
        asset.set('cpe', discovered_data["os_cpe"])
        changes.append((pattern, 'update', asset))

        # Add asset-level vulnerabilities using motif template
        for vuln_data in discovered_data["asset_vulnerabilities"]:
            vuln_change = self.output_motif.instantiate(
                "asset_vulnerability",
                match_on_override=asset,
                id=vuln_data["id"],
                source=vuln_data["source"],
                criteria=vuln_data["criteria"]
            )
            changes.append(vuln_change)

        # Process each processed port
        for port_info in discovered_data["processed_ports"]:
            port_data = port_info["port_data"]
            service_info = port_info["service_info"]

            # Create open port using motif template
            port_change = self.output_motif.instantiate(
                "discovered_port",
                match_on_override=asset,
                number=int(port_data["portid"]),
                protocol=port_data["protocol"]
            )
            changes.append(port_change)

            # Create service using motif template with service-specific data
            service_change = self.output_motif.instantiate(
                "discovered_service",
                **service_info["service_data"]
            )
            changes.append(service_change)

            # Add service-level vulnerabilities using motif template
            for vuln_data in service_info["service_vulnerabilities"]:
                vuln_change = self.output_motif.instantiate(
                    "service_vulnerability",
                    id=vuln_data["id"],
                    source=vuln_data["source"],
                    criteria=vuln_data["criteria"]
                )
                changes.append(vuln_change)

            # Create additional entities (like User entities for FTP) using motif template
            for user_data in service_info["user_entities"]:
                user_change = self.output_motif.instantiate(
                    "discovered_user",
                    username=user_data["username"]
                )
                changes.append(user_change)

        return changes

    def capture_state_change(
        self,
        artefacts: ArtefactManager,
        pattern: Pattern,
        output: ActionExecutionResult,
        conn=None
    ) -> StateChangeSequence:
        """
        Capture the state changes from the nmap output.
        """
        discovered_data = self.parse_output(artefacts, output, conn)
        changes = self.populate_output_motif(pattern, discovered_data, conn)
        return changes
