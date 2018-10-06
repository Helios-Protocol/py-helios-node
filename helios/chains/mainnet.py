from hvm.chains.mainnet import (
    BaseMainnetChain,
    MainnetChain
)

from helios.chains.coro import AsyncChainMixin
from helios.chains.light import LightDispatchChain


class MainnetFullChain(MainnetChain, AsyncChainMixin):
    pass


class MainnetLightDispatchChain(BaseMainnetChain, LightDispatchChain):
    pass
