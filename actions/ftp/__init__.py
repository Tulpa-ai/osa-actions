from .FTPAnonymousLogin import FTPAnonymousLogin
from .FTPLoginWithCredentials import FTPLoginWithCredentials
from .FtpRecursiveFileSearch import FtpRecursiveFileSearch
from .FtpDiscoverSSHUserAccounts import FtpDiscoverSSHUserAccounts
from .FtpDownloadFile import FtpDownloadFile

def get_actions() -> list:
    return [
        FTPAnonymousLogin(),
        FTPLoginWithCredentials(),
        FtpRecursiveFileSearch(),
        FtpDiscoverSSHUserAccounts(),
        FtpDownloadFile(),
    ]
