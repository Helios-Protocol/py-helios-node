from hvm.chains.ropsten import (
    RopstenChain,
)

from helios.chains.ropsten import (
    RopstenLightDispatchChain,
)
from helios.nodes.light import LightNode
from helios.nodes.full import FullNode


class RopstenFullNode(FullNode):
    chain_class = RopstenChain


class RopstenLightNode(LightNode):
    chain_class = RopstenLightDispatchChain
