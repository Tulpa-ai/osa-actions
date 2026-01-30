from . import (
    HashcatCrackAsRepHashes,
    HashcatCrackKerberosHashes,
)


def get_actions() -> list:
    """
    Returns a list of Action instances for the 'hashcat' collection.
    """
    return [
        HashcatCrackAsRepHashes.HashcatCrackAsRepHashes(),
        HashcatCrackKerberosHashes.HashcatCrackKerberosHashes(),
    ]
