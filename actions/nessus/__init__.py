from .NessusCSVImportAllAssets import NessusCSVImportAllAssets
from .NessusCSVImportCriticalAssets import NessusCSVImportCriticalAssets

def get_actions() -> list:
    return [NessusCSVImportAllAssets(), NessusCSVImportCriticalAssets()]