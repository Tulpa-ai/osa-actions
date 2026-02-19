from .LocalRecursiveFileSearch import LocalRecursiveFileSearch
from .IpRoute import IpRoute
from .PasswordlessSudoCheck import PasswordlessSudoCheck
from .ObtainShellOnExistingSession import ObtainShellOnExistingSession
from .ExtractCredentialsFromFile import ExtractCredentialsFromFile
from .StopService import StopService


def get_actions() -> list:
    return [LocalRecursiveFileSearch(), IpRoute(), PasswordlessSudoCheck(), ObtainShellOnExistingSession(), ExtractCredentialsFromFile(), StopService()]
