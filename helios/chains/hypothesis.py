from hvm.chains.hypothesis import HypothesisChain
from hvm.chains.mainnet import (
    BaseMainnetChain,
    MainnetChain
)

from helios.chains.coro import AsyncChainMixin


class HypothesisFullChain(HypothesisChain, AsyncChainMixin):
    pass

