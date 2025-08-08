from .FastNmapScan import FastNmapScan
from .SlowNmapScan import SlowNmapScan
from .AssetServiceScan import AssetServiceScan
from .AssetOSScan import AssetOSScan
from .NmapBannerScan import NmapBannerScan

def get_actions() -> list:
    return [FastNmapScan(), SlowNmapScan(), AssetServiceScan(), AssetOSScan(), NmapBannerScan()]