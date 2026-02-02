from . import (
    ImpacketGetNPUsers,
    ImpacketGetUserSPNs,
    ImpacketMSSQLClient,
    ImpacketSMBEnum,
)


def get_actions() -> list:
    """
    Returns a list of Action instances for the 'impacket' collection.
    """
    return [
        ImpacketGetNPUsers.ImpacketGetNPUsers(),
        ImpacketGetUserSPNs.ImpacketGetUserSPNs(),
        ImpacketSMBEnum.ImpacketSMBEnum(),
        ImpacketMSSQLClient.ImpacketMSSQLClient(),
    ]
