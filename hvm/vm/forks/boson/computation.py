
from hvm.vm.forks.helios_testnet import HeliosTestnetComputation
from hvm.vm.forks.helios_testnet.computation import HELIOS_TESTNET_PRECOMPILES

from .opcodes import BOSON_OPCODES


BOSON_PRECOMPILES = HELIOS_TESTNET_PRECOMPILES

class BosonComputation(HeliosTestnetComputation):
    """
    A class for all execution computations in the ``Byzantium`` fork.
    Inherits from :class:`~hvm.vm.forks.spurious_dragon.computation.SpuriousDragonComputation`
    """
    # Override
    opcodes = BOSON_OPCODES
    _precompiles = BOSON_PRECOMPILES
    

