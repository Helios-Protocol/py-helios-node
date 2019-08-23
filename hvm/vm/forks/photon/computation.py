
from hvm.vm.forks.boson import BosonComputation
from hvm.vm.forks.boson.computation import BOSON_PRECOMPILES

from .opcodes import PHOTON_OPCODES


PHOTON_PRECOMPILES = BOSON_PRECOMPILES

class PhotonComputation(BosonComputation):
    """
    A class for all execution computations in the ``Byzantium`` fork.
    Inherits from :class:`~hvm.vm.forks.spurious_dragon.computation.SpuriousDragonComputation`
    """
    # Override
    opcodes = PHOTON_OPCODES
    _precompiles = PHOTON_PRECOMPILES
    

