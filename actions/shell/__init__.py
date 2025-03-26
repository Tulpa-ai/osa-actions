from .LocalRecursiveFileSearch import LocalRecursiveFileSearch
from .IpRoute import IpRoute
from .PasswordlessSudoCheck import PasswordlessSudoCheck

def get_actions() -> list:
    return [LocalRecursiveFileSearch(), IpRoute(), PasswordlessSudoCheck()]