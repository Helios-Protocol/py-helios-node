from hvm.chains.ropsten import (
    BaseRopstenChain,
)

from helios.chains.light import LightDispatchChain


class RopstenLightDispatchChain(BaseRopstenChain, LightDispatchChain):
    pass
