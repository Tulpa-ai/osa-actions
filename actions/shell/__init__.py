from .LocalRecursiveFileSearch import LocalRecursiveFileSearch
from .IpRoute import IpRoute
from .PasswordlessSudoCheck import PasswordlessSudoCheck
from .ObtainShellOnExistingSession import ObtainShellOnExistingSession
from .CompressFiles import CompressFile
from .SendFile import SendFileUDP, SendFileHTTP, SendFileICMP


def get_actions() -> list:
    return [
        LocalRecursiveFileSearch(),
        IpRoute(),
        PasswordlessSudoCheck(),
        ObtainShellOnExistingSession(),
        CompressFile(),
        SendFileUDP(),
        SendFileHTTP(),
        SendFileICMP(),
    ]
