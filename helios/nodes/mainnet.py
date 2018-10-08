from helios.chains.mainnet import (
    MainnetFullChain,
)
from helios.nodes.full import FullNode


class MainnetFullNode(FullNode):
    chain_class = MainnetFullChain



