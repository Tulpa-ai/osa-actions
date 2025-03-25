import pathlib
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Optional, Union

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.action_utils import get_non_attack_ips, run_command, shell
from action_state_interface.exec import ActionExecutionError, ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from Session import SessionManager

base_path = pathlib.Path(__file__).parent.parent.parent
NON_ATTACK_IPS = get_non_attack_ips(base_path / 'non_attack_ips.txt')


class IpRoute(Action):
    """
    Implementation of IP route.
    """

    def __init__(self):
        super().__init__(
            "IpRoute", "T1016 System Network Configuration Discovery", "TA0007 Discovery", ["quiet", "fast"]
        )
        self.noise = 0.8
        self.impact = 0

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        return [f"Gain knowledge of network routes from {pattern.get('asset').get('ip_address')}"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check for IP route. This action finds other subnets that can be scanned.
        """
        session = Entity('Session', alias='session')
        # NB: this basic session type check will need to be removed when we do session management properly
        matching_sessions = kg.match(session).where("NOT session.protocol IN ['rsh', 'ftp', 'msf']")
        if not matching_sessions:
            return []

        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service')
        match_pattern = (
            asset.with_edge(Relationship('has'))
            .with_node(Entity('OpenPort', alias='openport'))
            .with_edge(Relationship('is_running'))
            .with_node(service)
            .combine(session)
        )

        res = kg.match(match_pattern).where(
            f"id(service) IN {[s.get('session').get('executes_on') for s in matching_sessions]} AND NOT session.protocol IN ['rsh', 'ftp', 'msf']"
        )
        return res

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use execute ip route.
        """
        session: Entity = pattern.get('session')
        session_id = session.get("id")
        channel = sessions.get_session(session_id)
        output = run_command(channel, "ip route")
        exit_status = 1 if "ip: not found" in output else 0
        result = ActionExecutionResult(
            command=["ip", "route"], stdout="".join(output), exit_status=exit_status, session=session_id
        )
        return result

    def capture_state_change(
        self, gdb: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Read the target subnet from an environment variable instead of from the IP route tables.
        """
        ip = pattern.get('asset').get('ip_address')
        subnet_pattern = r'\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b'
        matches = re.findall(subnet_pattern, output.stdout)
        changes: StateChangeSequence = []
        for match in matches:
            asset = Entity('Asset', alias='asset', ip_address=ip)
            subnet = Entity('Subnet', alias='subnet', network_address=match)
            sub_asset_pattern = asset.with_edge(Relationship('belongs_to')).with_node(subnet)
            changes.append((asset, "merge", sub_asset_pattern))
        return changes


def ftp_nmap_parser(gdb: GraphDB, ap_pattern: Pattern, nmap_output: list, svc_kwargs: dict) -> StateChangeSequence:
    """
    Parse FTP section of NMAP output.
    """
    ftp_section = re.search(r"21/tcp\s+open\s+ftp(.*?)MAC Address: ", nmap_output, re.DOTALL).group(1)
    anon_login = False
    users = []
    anon_login_pattern = r"Anonymous FTP login allowed"
    username_pattern = r"\d{2}:\d{2}\s+([^\s]+)$"
    for line in ftp_section.splitlines():
        if bool(re.search(anon_login_pattern, line)):
            anon_login = True
        usr_search = re.search(username_pattern, line)
        if usr_search:
            users.append(usr_search.group(1))
    service = Entity('Service', alias='service', anonymous_login=anon_login, **svc_kwargs)
    open_port = ap_pattern.get('openport')
    merge_pattern = open_port.with_edge(Relationship('is_running', direction='r')).with_node(service)
    changes: StateChangeSequence = [(ap_pattern, "merge", merge_pattern)]
    match_pattern = merge_pattern
    for username in users:
        usr_pattern = Entity('User', username=username).with_edge(Relationship('is_client')).with_node(service)
        changes.append((match_pattern, "merge", usr_pattern))
    return changes


def ssh_nmap_parser(gdb: GraphDB, ap_pattern: Pattern, nmap_output: list, svc_kwargs: dict) -> StateChangeSequence:
    """
    Parse SSH section of NMAP output.
    """
    service = Entity('Service', alias='service', **svc_kwargs)
    open_port = ap_pattern.get('openport')
    merge_pattern = open_port.with_edge(Relationship('is_running')).with_node(service)
    return [(ap_pattern, "merge", merge_pattern)]


def http_nmap_parser(gdb: GraphDB, ap_pattern: Pattern, nmap_output: list, svc_kwargs: dict) -> StateChangeSequence:
    """
    Parse HTTP section of NMAP output.
    """
    service = Entity('Service', alias='service', **svc_kwargs)
    open_port = ap_pattern.get('openport')
    merge_pattern = open_port.with_edge(Relationship('is_running')).with_node(service)
    return [(ap_pattern, "merge", merge_pattern)]


def nmap_parse_os_version_and_family(xml_str):
    """
    Given an XML string, extract the osmatch and osclass
    values which give us the name (and version range) of the OS
    and the standalone name of the OS (e.g.: "Linux").
    """
    root = ET.fromstring(xml_str)

    os_version = "unknown"
    os_family = "unknown"

    if osmatch := root.find(".//osmatch"):
        os_version = osmatch.get("name", "unknown")

        if osclass := osmatch.find(".//osclass"):
            os_family = osclass.get("osfamily", "unknown")

    return os_version, os_family


def extract_banner_from_nmap_report_xml(xml_str) -> Optional[str]:
    """
    Extracts a single '<script id="banner", output="...">' element
    from the supplied xml_str. If the entirety of the banner is not
    ASCII, returns None.
    """
    root = ET.fromstring(xml_str)
    banner_script_element = root.find(".//script[@id='banner']")
    if banner_script_element is not None:
        banner = banner_script_element.get("output")
        if banner.isascii():
            return banner

    return None


class FastNmapScan(Action):
    """
    Implementation of shallow NMAP scan.
    This NMAP scan is performed against subnets.
    """

    def __init__(self):
        super().__init__("FastNmapScan", "T1046 Network Service Discovery", "TA0007 Discovery", ["loud", "fast"])
        self.noise = 0.8
        self.impact = 0

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        return [
            f"Gain knowledge of network hosts on {pattern.get('subnet').get('network_address')}",
            f"Gain knowledge of network services on {pattern.get('subnet').get('network_address')}",
        ]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check for fast NMAP. This NMAP finds other assets on the
        network but does not identify open ports or services.
        """
        sub = Entity('Subnet', alias='subnet')
        return kg.get_matching(sub)

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use execute function from action_utils to perform NMAP scan.
        """
        subnet = pattern.get('subnet')
        res = shell(
            "nmap",
            ["-F", "-sS", "-n", subnet.get('network_address'), "--exclude", ",".join(NON_ATTACK_IPS)],
        )
        return res

    def capture_state_change(
        self, gdb: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Add Asset entities and OpenPort entities to knowledge graph.
        """
        ip_pattern = r"Nmap scan report for (\d{1,3}(?:\.\d{1,3}){3})"
        port_pattern = r"(\d+/tcp)\s+open"

        results = defaultdict(list)
        current_ip = None

        for line in output.stdout.splitlines():
            ip_match = re.match(ip_pattern, line)
            if ip_match:
                current_ip = ip_match.group(1)
                results.setdefault(current_ip, [])
            elif current_ip:
                port_match = re.match(port_pattern, line)
                if port_match:
                    results[current_ip].append(port_match.group(1))

        subnet = pattern.get('subnet')

        changes: StateChangeSequence = []
        for ip, ports in results.items():
            asset = Entity('Asset', alias='asset', ip_address=ip)
            sub_asset_pattern = asset.with_edge(Relationship('belongs_to')).with_node(subnet)
            changes.append((subnet, "merge", sub_asset_pattern))
            for port in ports:
                num, protocol = port.split('/')
                port_pattern = asset.with_edge(Relationship('has')).with_node(
                    Entity('OpenPort', alias='port', number=int(num), protocol=protocol)
                )
                changes.append((sub_asset_pattern, "merge", port_pattern))

        return changes


class AssetServiceScan(Action):
    """
    Identifies open ports and information about services which run
    on those ports. For example, if the asset is running an FTP server,
    it will test to see if the FTP server allows anonymous logins.
    """

    def __init__(self):
        super().__init__("AssetServiceScan", "T1046 Network Service Discovery", "TA0007 Discovery", ["loud", "fast"])

        self.noise = 0.9
        self.impact = 0
        self._parsers = {'ssh': ssh_nmap_parser, 'ftp': ftp_nmap_parser, 'http': http_nmap_parser}

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        return [
            f"Gain knowledge of network services on {pattern.get('asset').get('ip_address')}. "
            "May include additional details for some services, such as indicating if anonymous FTP is supported.",
        ]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check looking for assets which have not been scanned within
        the last hour.
        """
        asset = Entity('Asset', alias='asset')
        return kg.get_matching(asset)

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use execute function from action_utils to perform NMAP scan.
        """
        asset = pattern.get('asset')
        result = shell("nmap", ["-Pn", "-sT", "-A", "--top-ports", "1000", asset.get('ip_address')])
        return result

    def capture_state_change(
        self, gdb: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Returns OpenPort entities and Service entities. If there's an FTP service, that supports
        anonymous logons, that will also be added to the Service entity.
        """
        asset = pattern.get('asset')
        port_pattern = r"(\d+/tcp)\s+open"

        changes: StateChangeSequence = []
        for line in output.stdout.splitlines():
            port_match = re.match(port_pattern, line)
            if not port_match:
                continue
            num, protocol = port_match.group(1).split('/')
            open_port = Entity('OpenPort', alias='openport', number=int(num), protocol=protocol)
            merge_pattern = asset.with_edge(Relationship('has', direction='r')).with_node(open_port)
            changes.append((asset, "merge", merge_pattern))
            service_kwargs = {}
            service_kwargs['protocol'] = line.split()[2]
            service_kwargs['version'] = ' '.join(line.split()[3:])
            f = self._parsers.get(service_kwargs['protocol'])
            if f is not None:
                parser_changes = f(gdb, merge_pattern, output.stdout, service_kwargs)
                changes.extend(parser_changes)

        return changes


class HttpServiceScan(Action):
    """
    Implementation of DIRB scan against an HTTP service.
    """

    def __init__(self):
        super().__init__("HttpServiceScan", "T1083 File and Directory Discovery", "TA0007 Discovery", ["loud", "fast"])
        self.noise = 0.3
        self.impact = 0

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        ip = pattern.get('asset').get('ip_address')
        service = pattern.get('service')._id
        return [f"Gain knowledge to gain access to {ip} via service ({service})"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check looking for assets which are running an HTTP service.
        """
        asset = Entity('Asset', alias='asset')
        http_service = Entity('Service', alias='service', protocol='http')
        match_pattern = asset.directed_path_to(http_service)
        negate_pattern = http_service.directed_path_to(Entity('Directory'))
        res = kg.match(match_pattern).where_not(negate_pattern)
        return [p for p in res if not p.get('service').get('self_spawned')]

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use shell function from action_utils to perform DIRB scan.
        """
        ip = pattern.get('asset').get('ip_address')
        uuid = artefacts.search('small.txt')[0]
        wordlist_path = artefacts.get_path(uuid)
        scan_report = shell("dirb", [f"http://{ip}", wordlist_path])
        return scan_report

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Add Drive entities and Directory entities to knowledge graph.
        """
        directory_pattern = r"==> DIRECTORY: (http://\d{1,3}(?:\.\d{1,3}){3}/(\S+))/"
        url_pattern = r"\+ (http://\d{1,3}(?:\.\d{1,3}){3}/(\S+)) \(CODE:\d+\|SIZE:\d+\)"

        # Find all directories and individual URLs
        directories = re.findall(directory_pattern, output.stdout)
        urls = re.findall(url_pattern, output.stdout)

        # Combine both lists
        dirb_data = directories + urls

        service: Entity = pattern.get('service')
        asset: Entity = pattern.get('asset')
        ip = asset.get('ip_address')

        drive = Entity(type='Drive', alias='drive', location=f'HTTP://{ip}')

        merge_pattern = service.with_edge(Relationship(type='accesses')).with_node(drive)
        changes: StateChangeSequence = [(pattern, "match", merge_pattern)]

        match_pattern = asset.directed_path_to(service).directed_path_to(drive)

        for dir in dirb_data:
            directory = Entity(type='Directory', alias='dir', dirname=dir[1])

            merge_pattern = drive.with_edge(Relationship(type='has')).with_node(directory)
            changes.append((match_pattern, "merge", merge_pattern))

        return changes


class AssetOSScan(Action):
    """
    Implementation of NMAP scan against specific assets.
    This NMAP scan identifies information about operating system distributions and
    versions.
    """

    def __init__(self):
        super().__init__("AssetOSScan", "T1046 Network Service Discovery", "TA0007 Discovery", ["loud", "fast"])
        self.noise = 0.2
        self.impact = 0

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        return [
            f"Gain knowledge of the OS on {pattern.get('asset').get('ip_address')}",
        ]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check looking for assets which have not been scanned within
        the last hour.
        """
        asset = Entity('Asset', alias='asset')
        return kg.get_matching(asset)

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use execute function from action_utils to perform NMAP scan.
        """
        asset = pattern.get('asset')
        uuid = artefacts.placeholder("asset-os-scan.xml")
        out_path = artefacts.get_path(uuid)
        res = shell("nmap", ["-O", asset.get('ip_address'), "-oX", out_path])
        res.artefacts["xml_report"] = uuid
        return res

    def capture_state_change(
        self, gdb: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Add OpenPort entities and Service entities to knowledge graph.
        """

        with artefacts.open(output.artefacts["xml_report"], 'r') as f:
            content = f.read()

        try:
            os_version, os_family = nmap_parse_os_version_and_family(content)
        except ET.ParseError as e:
            raise ActionExecutionError(e)

        asset = pattern.get('asset')
        asset.set('os_version', os_version)
        asset.set('os_family', os_family)

        return [(pattern, 'update', asset)]


class NmapBannerScan(Action):
    """
    Implementation of NMAP Banner scan against specific assets.
    """

    def __init__(self):
        super().__init__("NmapBannerScan", "T1046 Network Service Discovery", "TA0007 Discovery", ["loud", "fast"])
        self.noise = 0.2
        self.impact = 0

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        port_num = pattern.get("port").get("number")
        port_proto = pattern.get("port").get("protocol")
        return [
            f"Capture the banner for port {port_num}/{port_proto} on {pattern.get('asset').get('ip_address')}",
        ]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        We need a specific Asset, and that asset must have an edge to an OpenPort.
        """
        asset = Entity('Asset', alias='asset')
        port = Entity('OpenPort', alias='port')
        match_pattern = asset.directed_path_to(port)
        res = kg.get_matching(match_pattern)
        return res

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Perform an nmap scan using the banner script.
        """
        asset = pattern.get('asset')
        port = pattern.get("port")
        uuid = artefacts.placeholder("asset-banner-scan.xml")
        out_path = artefacts.get_path(uuid)
        res = shell(
            "nmap",
            [
                "--script=banner",
                "--script-args",
                f"timeout=3,ports={port.get('number')}",
                asset.get("ip_address"),
                "-oX",
                out_path,
            ],
        )
        res.artefacts["xml_report"] = uuid

        return res

    def capture_state_change(
        self, gdb: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Add Banner attributes to knowledge graph.
        """
        try:
            with artefacts.open(output.artefacts["xml_report"], 'r') as f:
                contents = f.read()
        except KeyError as e:
            raise ActionExecutionError(e)

        try:
            banner = extract_banner_from_nmap_report_xml(contents)
        except ET.ParseError as e:
            raise ActionExecutionError(e)

        changes: StateChangeSequence = []
        if banner:
            port = pattern.get("port")
            port.set('banner', banner)
            changes.append((pattern, "update", port))

        return changes


actions = [IpRoute(), FastNmapScan(), AssetServiceScan(), HttpServiceScan(), AssetOSScan(), NmapBannerScan()]
