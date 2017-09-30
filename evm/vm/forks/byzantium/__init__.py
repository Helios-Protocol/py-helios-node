from ..spurious_dragon import SpuriousDragonVM

from .opcodes import BYZANTIUM_OPCODES


ByzantiumVM = SpuriousDragonVM.configure(
    name='ByzantiumVM',
    # opcodes
    opcodes=BYZANTIUM_OPCODES,
)
