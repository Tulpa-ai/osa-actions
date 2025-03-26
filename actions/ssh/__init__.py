from .SshLoginPubkey import SshLoginPubkey
from .SshLoginWithCredentials import SshLoginWithCredentials
from .DiscoverSSHAuthMethods import DiscoverSSHAuthMethods

def get_actions() -> list:
    return [SshLoginPubkey(), SshLoginWithCredentials(), DiscoverSSHAuthMethods()]