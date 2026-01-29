from .LocalRecursiveFileSearch import LocalRecursiveFileSearch
from .IpRoute import IpRoute
from .PasswordlessSudoCheck import PasswordlessSudoCheck
from .ObtainShellOnExistingSession import ObtainShellOnExistingSession
from .DiskWipe import DiskWipe


def get_actions() -> list:
    return [
        LocalRecursiveFileSearch(),
        IpRoute(),
        PasswordlessSudoCheck(),
        ObtainShellOnExistingSession(),
        DiskWipe(),
    ]