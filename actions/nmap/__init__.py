from .FastNmapScan import FastNmapScan
from .SlowNmapScan import SlowNmapScan
from .NmapAssetScan import NmapAssetScan
from .NmapVulnerabilityScan import NmapVulnerabilityScan

def get_actions() -> list:
    return [FastNmapScan(), SlowNmapScan(), NmapAssetScan(), NmapVulnerabilityScan()]