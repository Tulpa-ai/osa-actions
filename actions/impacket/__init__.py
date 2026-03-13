from . import (
    ImpacketGetNPUsers,
    ImpacketGetUserSPNs,
    ImpacketMSSQLClient,
)


def get_actions() -> list:
    """
    Returns a list of Action instances for the 'impacket' collection.
    """
    return [
        ImpacketGetNPUsers.ImpacketGetNPUsers(),
        ImpacketGetUserSPNs.ImpacketGetUserSPNs(),
        ImpacketMSSQLClient.ImpacketMSSQLClient(),
    ]
