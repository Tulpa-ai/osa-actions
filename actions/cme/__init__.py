from . import (
    CMESMBReconnaissance,
    CMEUserReconnaissance,
)


def get_actions() -> list:
    """
    Returns a list of Action instances for the 'cme' collection.
    """
    return [
        CMESMBReconnaissance.CMESMBReconnaissance(),
        CMEUserReconnaissance.CMEUserReconnaissance(),
    ]
