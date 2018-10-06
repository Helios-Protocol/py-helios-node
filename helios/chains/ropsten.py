from hvm.chains.ropsten import (
    BaseRopstenChain,
    RopstenChain
)

from helios.chains.coro import AsyncChainMixin
from helios.chains.light import LightDispatchChain


class RopstenFullChain(RopstenChain, AsyncChainMixin):
    pass


class RopstenLightDispatchChain(BaseRopstenChain, LightDispatchChain):
    pass
