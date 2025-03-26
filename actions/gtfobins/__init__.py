from .BusyBoxGTFO import BusyBoxGTFO
from .MakeGTFO import MakeGTFO

def get_actions() -> list:
    return [BusyBoxGTFO(), MakeGTFO()]