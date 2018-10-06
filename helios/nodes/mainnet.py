from helios.chains.mainnet import (
    MainnetFullChain,
    MainnetLightDispatchChain,
)
from helios.nodes.light import LightNode
from helios.nodes.full import FullNode


class MainnetFullNode(FullNode):
    chain_class = MainnetFullChain


class MainnetLightNode(LightNode):
    chain_class = MainnetLightDispatchChain
