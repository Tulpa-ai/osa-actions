from .NessusCSVImportCriticalAssets import NessusCSVImportCriticalAssets
from .NessusCSVImportHighAssets import NessusCSVImportHighAssets
from .NessusCSVImportMediumAssets import NessusCSVImportMediumAssets
from .NessusCSVImportLowAssets import NessusCSVImportLowAssets

def get_actions() -> list:
    return [
        NessusCSVImportCriticalAssets(),
        NessusCSVImportHighAssets(),
        NessusCSVImportMediumAssets(),
        NessusCSVImportLowAssets()
    ]