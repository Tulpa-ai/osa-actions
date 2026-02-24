from .LocalRecursiveFileSearch import LocalRecursiveFileSearch
from .IpRoute import IpRoute
from .PasswordlessSudoCheck import PasswordlessSudoCheck
from .ObtainShellOnExistingSession import ObtainShellOnExistingSession
from .ExtractCredentialsFromFile import ExtractCredentialsFromFile
from .CompressFiles import CompressFiles
from .SendFile import SendFileUDP, SendFileHTTP, SendFileICMP


def get_actions() -> list:
    return [
        LocalRecursiveFileSearch(),
        IpRoute(),
        PasswordlessSudoCheck(),
        ObtainShellOnExistingSession(),
        CompressFiles(),
        SendFileUDP(),
        SendFileHTTP(),
        SendFileICMP(),
    ]
