from . import (
    AdalancheFetchComputerAccounts,
    AdalancheFetchUsers,
    AdalancheIngestData,
)


def get_actions() -> list:
    """
    Returns a list of Action instances for the 'adalanche' collection.
    """
    return [
        AdalancheIngestData.AdalancheIngestData(),
        AdalancheFetchComputerAccounts.AdalancheFetchComputerAccounts(),
        AdalancheFetchUsers.AdalancheFetchUsers(),
    ]
