from .LocalRecursiveFileSearch import LocalRecursiveFileSearch
from .IpRoute import IpRoute
from .PasswordlessSudoCheck import PasswordlessSudoCheck
from .ObtainShellOnExistingSession import ObtainShellOnExistingSession
from .DeleteFile import DeleteFile


def get_actions() -> list:
    return [LocalRecursiveFileSearch(), IpRoute(), PasswordlessSudoCheck(), ObtainShellOnExistingSession(), DeleteFile()]
