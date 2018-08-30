from ..homestead.computation import HomesteadComputation

from .opcodes import TANGERINE_WHISTLE_OPCODES


class TangerineWhistleComputation(HomesteadComputation):
    """
    A class for all execution computations in the ``TangerineWhistle`` fork.
    Inherits from :class:`~hvm.vm.forks.homestead.computation.HomesteadComputation`
    """
    # Override
    opcodes = TANGERINE_WHISTLE_OPCODES
