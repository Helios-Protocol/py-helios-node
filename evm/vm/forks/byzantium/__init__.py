from cytoolz import (
    merge,
)

from evm import precompiles
from evm.utils.address import (
    force_bytes_to_address,
)

from ..frontier import FRONTIER_PRECOMPILES
from ..spurious_dragon import SpuriousDragonVM

from .opcodes import BYZANTIUM_OPCODES
from .blocks import ByzantiumBlock


BYZANTIUM_PRECOMPILES = merge(
    FRONTIER_PRECOMPILES,
    {
        force_bytes_to_address(b'\x05'): precompiles.precompile_modexp,
    },
)


ByzantiumVM = SpuriousDragonVM.configure(
    name='ByzantiumVM',
    # precompiles
    _precompiles=BYZANTIUM_PRECOMPILES,
    # opcodes
    opcodes=BYZANTIUM_OPCODES,
    # RLP
    _block_class=ByzantiumBlock,
)
