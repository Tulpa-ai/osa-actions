import os
import re
from ftplib import FTP, error_perm
from pathlib import Path
from typing import Any, Union

from fuzzywuzzy import fuzz

from action_state_interface.action import Action, StateChangeSequence
from action_state_interface.exec import ActionExecutionError, ActionExecutionResult
from artefacts.ArtefactManager import ArtefactManager
from kg_api import Entity, GraphDB, MultiPattern, Pattern, Relationship
from Session import SessionManager

FILES_AND_DIRS_TO_IGNORE = ['.', '..']


def list_files_recursive(ftp, path='/', depth=1, max_depth=2, file_list=None) -> list[str]:
    """
    Recursively list files and directories on an FTP server up to a specified depth,
    including hidden files, and return a list of all discovered files with paths.

    Args:
        ftp (FTP): The FTP connection object.
        path (str): The directory path to start from.
        depth (int): The current depth of recursion.
        max_depth (int): The maximum depth to search.
        file_list (list): List to store discovered files with paths.

    Returns:
        list: A list of all discovered files with their full paths.
    """
    if file_list is None:
        file_list = []

    if depth > max_depth:
        return file_list

    try:
        ftp.cwd(path)
    except error_perm:
        return file_list

    items = []
    try:
        ftp.retrlines('LIST -a', items.append)
    except error_perm:
        ftp.retrlines('LIST', items.append)

    for item in items:
        parts = item.split()
        name = parts[-1]
        if name in FILES_AND_DIRS_TO_IGNORE:
            continue
        item_type = item[0]
        if item_type == 'd':
            list_files_recursive(ftp, path=f"{path}{name}/", depth=depth + 1, max_depth=max_depth, file_list=file_list)
        elif item_type == "l":  # Ignore symbolic links for now
            continue
        else:
            full_path = f"{path}{name}"
            file_list.append(full_path)

    ftp.cwd('..')

    return file_list


def get_ssh_user_accounts(path_list) -> list[str]:
    """Extracts unique SSH user account names from a list of file paths.

    This function identifies user account names by looking for the `.ssh` directory
    in each path and extracting the preceding directory name, which is assumed to
    be the username.

    Args:
        path_list (list[str]): A list of file paths.

    Returns:
        list[str]: A list of unique SSH user account names.
    """
    ssh_users = set()
    for path in path_list:
        parts = path.split(os.sep)
        if '.ssh' in parts:
            index = parts.index('.ssh')
            if index > 0:
                ssh_users.add(parts[index - 1])
    return list(ssh_users)


def filter_files_by_wordlist(file_list: list[str], wordlist: list[str], similarity_thresh: float = 80) -> list[str]:
    """Filters a list of files based on their similarity to words in a given wordlist.

    This function compares file names (including base names) to words in the wordlist
    using fuzzy string matching. If the similarity ratio meets or exceeds the threshold,
    the file is included in the output list.

    Args:
        file_list (list[str]): A list of file paths to filter.
        wordlist (list[str]): A list of words to compare against file names.
        similarity_thresh (float, optional): The minimum similarity percentage (0-100)
                                             required to consider a match. Defaults to 80.

    Returns:
        list[str]: A list of files that match the wordlist based on similarity threshold.
    """
    base_names_dict = {os.path.basename(file): file for file in file_list}
    all_files = list(set(file_list + list(base_names_dict.keys())))
    out = []
    for file in all_files:
        for word in wordlist:
            if fuzz.ratio(file, word) >= similarity_thresh:
                out.append(base_names_dict.get(file, file))
    return out


def filter_files_by_regex(file_list, pattern):
    """
    Search for file names that match REGEX.
    """
    regex = re.compile(pattern)
    return [file for file in file_list if regex.search(file)]


def download_file(ftp, remote_file_path, local_file_path):
    """
    Download file from FTP server.

    This function checks if the path represents an actual file and attempts to
    do some minor corrections to the path if the file is not found.
    """
    items = []
    ftp.retrlines(f'LIST -a {remote_file_path}', items.append)

    if not items:
        ftp.retrlines(f'LIST -a /home{remote_file_path}', items.append)
        remote_file_path = f"/home{remote_file_path}"

    if not items:
        ftp.retrlines(f'LIST -a ~{remote_file_path}', items.append)
        remote_file_path = f"~{remote_file_path}"

    with open(local_file_path, 'wb') as local_file:
        ftp.retrbinary(f"RETR {remote_file_path}", local_file.write)


class FTPAnonymousLogin(Action):
    """
    Establish an FTP session on an FTP server which allows anonymous login.
    This action is performed against Service entities.
    """

    def __init__(self):
        super().__init__("FTPAnonymousLogin", "T1078 Valid Accounts", "TA0001 Initial Access", ["quiet", "fast"])
        self.noise = 0.1
        self.impact = 0.6

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        return [
            f"Gain a session on FTP service ({pattern.get('service')._id}) on {pattern.get('asset').get('ip_address')}"
        ]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check looking for FTP Service entities which allow anonymous
        logins.
        """
        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service', protocol='ftp', anonymous_login=True)
        pattern = (
            asset.with_edge(Relationship('has', direction='r'))
            .with_node(Entity('OpenPort'))
            .with_edge(Relationship('is_running', direction='r'))
            .with_node(service)
        )
        return kg.get_matching(pattern)

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use FTP library to establish FTP session.
        """
        asset: Entity = pattern.get('asset')
        ip_address = asset.get('ip_address')
        username, password = "anonymous", ""
        with FTP(host=ip_address, user=username, passwd=password):
            pass
        sess_id = sessions.add_session(
            {"protocol": "ftp", "host": ip_address, "username": username, "password": password}
        )
        return ActionExecutionResult(command=["AUTH", username], session=sess_id)

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Add FTP session object to knowledge graph.
        """
        service = pattern.get('service')
        session = Entity('Session', alias='session', protocol='ftp', id=output.session, executes_on=service._id)
        return [(None, "merge", session)]


class FTPLoginWithCredentials(Action):
    """
    Establish an FTP session on an FTP server using user credentials.
    This action is performed against Service entities.
    """

    def __init__(self):
        super().__init__("FTPLoginWithCredentials", "T1078 Valid Accounts", "TA0001 Initial Access", ["quiet", "fast"])
        self.noise = 0.0
        self.impact = 0.5

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        ip = pattern.get('asset').get('ip_address')
        user = pattern.get('credentials').get('username')
        service = pattern.get('service')._id
        return [f"Gain a session on FTP service ({service}) on {ip} as user: {user}"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check looking for FTP Service entities which allow anonymous
        logins.
        """
        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service', protocol='ftp')
        creds = Entity('Credentials', alias='credentials')
        pattern = (
            asset.with_edge(Relationship('has', direction='r'))
            .with_node(Entity('OpenPort'))
            .with_edge(Relationship('is_running', direction='r'))
            .with_node(service)
            .with_edge(Relationship('secured_with', direction='l'))
            .with_node(creds)
        )
        return kg.match(pattern).where("credentials.username <> 'anonymous'")

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Use FTP library to establish FTP session.
        """
        asset: Entity = pattern.get('asset')
        ip_address = asset.get('ip_address')
        creds = pattern.get('credentials')
        username = creds.get("username")
        password = creds.get("password")
        with FTP(host=ip_address, user=username, passwd=password):
            pass
        sess_id = sessions.add_session(
            {"protocol": "ftp", "host": ip_address, "username": username, "password": password}
        )
        return ActionExecutionResult(command=["USER", username, "PASS", password], session=sess_id)

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Add FTP session object to knowledge graph.
        """
        service = pattern.get('service')
        session = Entity('Session', alias='session', protocol='ftp', id=output.session, executes_on=service._id)
        return [(None, "merge", session)]


class FtpRecursiveFileSearch(Action):
    """
    Implementation of recursive function to list files on an FTP server.
    Function can be parameterised to search for files at varying depths in
    file system.
    This action is performed against FTP services.
    """

    def __init__(self):
        super().__init__(
            "FtpRecursiveFileSearch", "T1083 File and Directory Discovery", "TA0007 Discovery", ["quiet", "fast"]
        )
        self.noise = 0.2
        self.impact = 0.8

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Return expected outcome of action.
        """
        ip = pattern.get('asset').get('ip_address')
        service = pattern.get('service')._id
        return [f"Search for interesting files on FTP service ({service}) on {ip}"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        get_target_patterns check looking for FTP Service entities on which the agent
        has an active session.
        """
        session = Entity('Session', alias='session', protocol='ftp')
        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service', protocol='ftp')
        match_pattern = (
            asset.with_edge(Relationship('has'))
            .with_node(Entity('OpenPort', alias='openport'))
            .with_edge(Relationship('is_running'))
            .with_node(service)
            .combine(session)
        )
        negate_pattern = service.directed_path_to(Entity('File'))
        res = kg.match(match_pattern).where_not(negate_pattern)
        return res

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> str:
        """
        Use FTP library to recursively search for files.
        """
        uuid = artefacts.search('interesting_file_names.txt')[0]
        with artefacts.open(uuid, "r") as f:
            wordlist = {line.strip() for line in f}
        wordlist.discard('')
        session: Entity = pattern.get('session')
        session_id = session.get('id')
        ftp_connection_details: dict = sessions.get_session(session_id)
        hostname = ftp_connection_details["host"]
        username = ftp_connection_details["username"]
        password = ftp_connection_details["password"]
        with FTP(host=hostname, user=username, passwd=password) as ftp_session:
            all_files = list_files_recursive(ftp_session, path='/', max_depth=3)
        interesting_files = filter_files_by_wordlist(all_files, wordlist)
        ip = pattern.get('asset').get('ip_address')
        uuid = artefacts.placeholder(f'FTP-directories-on-{ip}')
        with artefacts.open(uuid, "wb") as f:
            for file in all_files:
                f.write(file.encode("utf-8") + b'\n')
        return interesting_files

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: Any
    ) -> StateChangeSequence:
        """
        Add interesting files to knowledge graph.
        (In future extend this function to add all files).
        """

        changes: StateChangeSequence = []

        if len(output) == 0:
            return changes

        asset: Entity = pattern.get('asset')
        ftp_service: Entity = pattern.get('service')
        ip_address = asset.get('ip_address')

        ftp_match_pattern = (
            asset.with_edge(Relationship('has'))
            .with_node(Entity('OpenPort'))
            .with_edge(Relationship('is_running'))
            .with_node(ftp_service)
        )

        drive = Entity('Drive', alias='drive', location=f'FTP://{ip_address}/')
        service_drive_pattern = ftp_service.with_edge(Relationship('accesses', direction='r')).with_node(drive)
        changes.append((ftp_match_pattern, 'merge_if_not_match', service_drive_pattern))

        ftp_drive_pattern = ftp_match_pattern.with_edge(Relationship('accesses', direction='r')).with_node(drive)

        for filename in output:
            path_list = [f for f in filename.split('/') if len(f) > 0]
            filename = path_list.pop()

            match_pattern = ftp_drive_pattern
            merge_pattern = drive

            for index, path in enumerate(path_list):
                directory = Entity('Directory', alias=f'directory{index}', dirname=path)
                merge_pattern = merge_pattern.with_edge(Relationship('has', direction='r')).with_node(directory)
                changes.append((match_pattern, "merge_if_not_match", merge_pattern))
                match_pattern = match_pattern.with_edge(Relationship('has', direction='r')).with_node(directory)
                merge_pattern = directory
            merge_pattern = merge_pattern.with_edge(Relationship('has', direction='r')).with_node(
                Entity(type='File', filename=filename)
            )
            changes.append((match_pattern, "merge_if_not_match", merge_pattern))

        return changes


class FtpDiscoverSSHUserAccounts(Action):
    """Action to discover SSH user accounts by analyzing file structures exposed via FTP.

    This class implements a recursive function to search for files within an FTP service,
    particularly looking for `.ssh` directories that may indicate SSH user accounts.
    The action is performed against FTP services to gather intelligence on potential
    SSH users linked to discovered assets.
    """

    def __init__(self):
        """
        Initialize the FtpDiscoverSSHUserAccounts action with metadata and impact values.
        """
        super().__init__(
            "FtpDiscoverSSHUserAccounts", "T1083 File and Directory Discovery", "TA0007 Discovery", ["quiet", "fast"]
        )
        self.noise = 0.2
        self.impact = 0.2

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """Define the expected outcome of the action.

        Args:
            pattern (Pattern): The pattern containing asset information.

        Returns:
            list[str]: A list containing a description of the expected outcome.
        """
        ip = pattern.get('asset').get('ip_address')
        service = pattern.get('service')._id
        return [f"Use the file system using the ftp service ({service}) on {ip} to infer SSH user accounts"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """Retrieve target patterns matching FTP services where the agent has an active session.

        This function identifies assets running FTP services and containing `.ssh` directories,
        which may indicate the presence of SSH user accounts.

        Args:
            kg (GraphDB): The knowledge graph database storing entity relationships.

        Returns:
            list[Union[Pattern, MultiPattern]]: A list of matching patterns for target assets.
        """
        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service', protocol='ftp')
        match_pattern = (
            asset.with_edge(Relationship('has'))
            .with_node(Entity('OpenPort', alias='openport'))
            .with_edge(Relationship('is_running'))
            .with_node(service)
            .points_to(Entity('Drive'))
            .directed_path_to(Entity('Directory', dirname='.ssh'))
        )
        res = kg.get_matching(match_pattern)
        return res

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> str:
        """Perform a recursive search for files using the FTP library.

        This function retrieves a list of all files within a targeted FTP service
        and returns their paths as a list.

        Args:
            sessions (SessionManager): Manages active sessions.
            artefacts (ArtefactManager): Handles stored artefacts.
            pattern (Pattern): Contains asset-related information.

        Returns:
            list[str]: A list of file paths found in the FTP service.
        """
        ip = pattern.get('asset').get('ip_address')
        uuid = artefacts.search(f'FTP-directories-on-{ip}')[0]
        with artefacts.open(uuid, "rb") as f:
            all_files = [line.decode("utf-8").rstrip('\n') for line in f.readlines()]
        return all_files

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: Any
    ) -> StateChangeSequence:
        """Capture and update the knowledge graph based on discovered SSH user accounts.

        This function processes the output from the FTP discovery, extracts SSH user accounts,
        and updates the knowledge graph by linking users to the SSH service running on the asset.

        Args:
            kg (GraphDB): The knowledge graph database storing entity relationships.
            artefacts (ArtefactManager): Manages stored artefacts.
            pattern (Pattern): Contains asset-related information.
            output (list[str]): The list of discovered file paths.

        Returns:
            StateChangeSequence: A sequence of state changes to be applied to the knowledge graph.
        """
        changes: StateChangeSequence = []

        ssh_users = get_ssh_user_accounts(output)

        asset = pattern.get('asset')
        ftp_service = Entity('Service', alias='ftp_service', protocol='ftp')
        ssh_service = Entity('Service', alias='ssh_service', protocol='ssh')
        is_running = Relationship('is_running', direction='r')
        asset_port = asset.with_edge(Relationship('has', direction='r')).with_node(Entity('OpenPort'))
        asset_ftp_pattern = asset_port.with_edge(is_running).with_node(ftp_service)
        asset_ssh_pattern = asset_port.with_edge(is_running).with_node(ssh_service)

        if len(ssh_users) > 0:
            changes.append((asset, 'merge_if_not_match', asset_ssh_pattern))

        for index, user in enumerate(ssh_users):
            user = Entity('User', alias=f'user{index}', username=user)
            user_ftp_pattern = ftp_service.with_edge(Relationship('is_client', direction='l')).with_node(user)
            changes.append((asset_ftp_pattern, 'merge_if_not_match', user_ftp_pattern))
            user_pattern = asset_ftp_pattern.with_edge(Relationship('is_client', direction='l')).with_node(user)
            user_ssh_pattern = ssh_service.with_edge(Relationship('is_client', direction='l')).with_node(user)
            combined = asset_ssh_pattern.combine(user_pattern)
            changes.append((combined, 'merge_if_not_match', user_ssh_pattern))

        return changes


class FtpDownloadFile(Action):
    """
    Implements a recursive function to list and download files from an FTP server.

    This action searches for files within an FTP service and can be configured
    to explore varying depths of the file system. It operates on FTP services
    where the agent has an active session.
    """

    def __init__(self):
        """
        Initializes the FtpDownloadFile action with specific attributes.

        Inherits from the Action class and sets the action name, tactic,
        technique, and operational flags. Also initializes noise and impact levels.
        """
        super().__init__("FtpDownloadFile", "T1083 File and Directory Discovery", "TA0007 Discovery", ["quiet", "fast"])
        self.noise = 0.2
        self.impact = 0.8

    def expected_outcome(self, pattern: Pattern) -> list[str]:
        """
        Determines the expected outcome of the action based on the provided pattern.

        Args:
            pattern (Pattern): The target pattern containing details about the file and asset.

        Returns:
            list[str]: A description of the expected outcome, including the file
            to be downloaded and the target FTP service.
        """
        filename = pattern.get('path')[-1].get('filename')
        ip = pattern.get('asset').get('ip_address')
        session = pattern.get('session')._id
        service = pattern.get('service')._id
        return [f"Download file {filename} from FTP service ({service}) on {ip} using session ({session})"]

    def get_target_patterns(self, kg: GraphDB) -> list[Union[Pattern, MultiPattern]]:
        """
        Identifies target patterns by searching for FTP services on which the agent has an active session.

        Args:
            kg (GraphDB): The knowledge graph database used to retrieve matching entities.

        Returns:
            list[Union[Pattern, MultiPattern]]: A list of patterns representing target FTP services and files.
        """
        session = Entity('Session', alias='session', protocol='ftp')
        asset = Entity('Asset', alias='asset')
        service = Entity('Service', alias='service', protocol='ftp')
        drive = Entity('Drive', alias='drive')
        service_pattern = (
            asset.with_edge(Relationship('has'))
            .with_node(Entity('OpenPort', alias='openport'))
            .with_edge(Relationship('is_running'))
            .with_node(service)
            .connects_to(drive)
        )
        file_pattern = drive.directed_path_to(Entity('File', alias='file'))
        file_pattern.set_alias('path')
        match_pattern = service_pattern.combine(file_pattern).combine(session)
        res = kg.get_matching(match_pattern)
        return res

    def function(self, sessions: SessionManager, artefacts: ArtefactManager, pattern: Pattern) -> ActionExecutionResult:
        """
        Executes the FTP file download operation.

        This method establishes an FTP connection using session credentials,
        navigates the directory structure based on the pattern, and downloads
        the target file to a local path.

        Args:
            sessions (SessionManager): Manages active sessions for network interactions.
            artefacts (ArtefactManager): Manages retrieved artefacts and file storage.
            pattern (Pattern): Contains details about the target file and FTP session.

        Returns:
            ActionExecutionResult: Which contains the FTP GET command along with an artefact
            called "downloaded_file_id" which maps to the AM UUID for the fetched file.
        """
        session: Entity = pattern.get('session')
        session_id = session.get('id')
        ftp_connection_details: dict = sessions.get_session(session_id)
        hostname = ftp_connection_details["host"]
        username = ftp_connection_details["username"]
        password = ftp_connection_details["password"]

        path_pattern: Pattern = pattern.get('path')
        ftp_path = Path('/')
        for g_obj in path_pattern:
            if g_obj.type == 'Directory':
                ftp_path = ftp_path / g_obj.get('dirname')
            if g_obj.type == 'File':
                ftp_path = ftp_path / g_obj.get('filename')

        with FTP(host=hostname, user=username, passwd=password) as ftp_session:
            uuid = artefacts.placeholder(ftp_path.name)
            local_path = artefacts.get_path(uuid)

            try:
                download_file(ftp_session, ftp_path, local_path)
            except error_perm:
                raise ActionExecutionError("File can't be downloaded")

            os.chmod(local_path, 0o600)

        return ActionExecutionResult(
            command=["GET", f"{ftp_path}"], session=session_id, artefacts={"downloaded_file_id": uuid}
        )

    def capture_state_change(
        self, kg: GraphDB, artefacts: ArtefactManager, pattern: Pattern, output: ActionExecutionResult
    ) -> StateChangeSequence:
        """
        Captures and records changes in the system state after the file download.

        Args:
            kg (GraphDB): The knowledge graph database used to track system states.
            artefacts (ArtefactManager): Manages retrieved artefacts.
            pattern (Pattern): The target pattern of the executed action.
            output (ActionExecutionResult): May contain the resulting artefact UUID.

        Returns:
            StateChangeSequence: A list of state change operations reflecting the
            updated file status in the system.
        """
        changes: StateChangeSequence = []
        service_pattern = pattern[0]
        file_pattern = pattern.get('path')
        file_pattern[-1].alias = 'file'
        match_pattern = service_pattern.combine(file_pattern)
        file = file_pattern[-1].copy()
        file.alias = 'file'
        file.set('artefact_id', output.artefacts.get("downloaded_file_id"))
        changes.append((match_pattern, 'update', file))
        return changes


actions = [
    FTPAnonymousLogin(),
    FTPLoginWithCredentials(),
    FtpRecursiveFileSearch(),
    FtpDiscoverSSHUserAccounts(),
    FtpDownloadFile(),
]
