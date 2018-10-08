from hvm.chains.mainnet import (
    BaseMainnetChain,
    MainnetChain
)

from helios.chains.coro import AsyncChainMixin


class MainnetFullChain(MainnetChain, AsyncChainMixin):
    pass

