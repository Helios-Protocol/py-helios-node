from cytoolz import (
    merge,
)

from evm import precompiles
from evm.utils.address import (
    force_bytes_to_address,
)

from ..frontier import FRONTIER_PRECOMPILES
from ..spurious_dragon import SpuriousDragonVM

from .headers import create_byzantium_header_from_parent
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
    # Methods
    create_header_from_parent=staticmethod(create_byzantium_header_from_parent),
)
