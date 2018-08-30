from cytoolz import (
    merge,
)

from hvm import precompiles
from hvm.utils.address import (
    force_bytes_to_address,
)
from hvm.vm.forks.frontier.computation import FRONTIER_PRECOMPILES
from hvm.vm.forks.spurious_dragon.computation import SpuriousDragonComputation

from .opcodes import BYZANTIUM_OPCODES

BYZANTIUM_PRECOMPILES = merge(
    FRONTIER_PRECOMPILES,
    {
        force_bytes_to_address(b'\x05'): precompiles.modexp,
        force_bytes_to_address(b'\x06'): precompiles.ecadd,
        force_bytes_to_address(b'\x07'): precompiles.ecmul,
        force_bytes_to_address(b'\x08'): precompiles.ecpairing,
    },
)


class ByzantiumComputation(SpuriousDragonComputation):
    """
    A class for all execution computations in the ``Byzantium`` fork.
    Inherits from :class:`~hvm.vm.forks.spurious_dragon.computation.SpuriousDragonComputation`
    """
    # Override
    opcodes = BYZANTIUM_OPCODES
    _precompiles = BYZANTIUM_PRECOMPILES
