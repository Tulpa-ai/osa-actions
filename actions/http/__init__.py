from .HttpServiceScan import HttpServiceScan
from .HttpGobuster import HttpGobuster
#from .HttpDownloadFile import HttpDownloadFile
from .HttpGetLoginPages import HttpGetLoginPages
from .HttpGetAllPages import HttpGetAllPages

def get_actions() -> list:
    return [HttpServiceScan(), HttpGobuster(), HttpGetLoginPages(), HttpGetAllPages()]