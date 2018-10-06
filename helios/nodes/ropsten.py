from helios.chains.ropsten import (
    RopstenFullChain,
    RopstenLightDispatchChain,
)
from helios.nodes.light import LightNode
from helios.nodes.full import FullNode


class RopstenFullNode(FullNode):
    chain_class = RopstenFullChain


class RopstenLightNode(LightNode):
    chain_class = RopstenLightDispatchChain
