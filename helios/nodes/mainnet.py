from hvm.chains.mainnet import (
    MainnetChain,
)

#from helios.chains.mainnet import (
#    MainnetLightDispatchChain,
#)
#from helios.nodes.light import LightNode
from helios.nodes.full import FullNode


class MainnetFullNode(FullNode):
    chain_class = MainnetChain


#class MainnetLightNode(LightNode):
#    chain_class = MainnetLightDispatchChain
