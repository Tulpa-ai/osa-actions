from .SMBShareEnumeration import SMBShareEnumeration

def get_actions() -> list:
    return [SMBShareEnumeration()]