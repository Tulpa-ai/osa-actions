from .NessusCSVImportCriticalAssets import NessusCSVImportCriticalAssets

def get_actions() -> list:
    return [NessusCSVImportCriticalAssets()]