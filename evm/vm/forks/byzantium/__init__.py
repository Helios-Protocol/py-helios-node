from ..spurious_dragon import SpuriousDragonVM

from .opcodes import BYZANTIUM_OPCODES
from .blocks import ByzantiumBlock


ByzantiumVM = SpuriousDragonVM.configure(
    name='ByzantiumVM',
    # opcodes
    opcodes=BYZANTIUM_OPCODES,
    # RLP
    _block_class=ByzantiumBlock,
)
