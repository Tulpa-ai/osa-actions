from .FastNmapScan import FastNmapScan
from .AssetServiceScan import AssetServiceScan
from .AssetOSScan import AssetOSScan
from .NmapBannerScan import NmapBannerScan

def get_actions() -> list:
    return [FastNmapScan(), AssetServiceScan(), AssetOSScan(), NmapBannerScan()]