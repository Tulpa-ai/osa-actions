from .FastNmapScan import FastNmapScan
from .SlowNmapScan import SlowNmapScan
from .NmapAssetScan import NmapAssetScan

def get_actions() -> list:
    return [FastNmapScan(), SlowNmapScan(), NmapAssetScan()]