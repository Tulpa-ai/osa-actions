from .HydraBruteForceAction import HydraBruteForceAction
from .PasswordSprayAction import PasswordSprayAction

def get_actions() -> list:
    return [HydraBruteForceAction(), PasswordSprayAction()]