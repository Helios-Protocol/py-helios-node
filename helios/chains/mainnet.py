from hvm.chains.mainnet import (
    BaseMainnetChain,
)

from helios.chains.light import LightDispatchChain


class MainnetLightDispatchChain(BaseMainnetChain, LightDispatchChain):
    pass
