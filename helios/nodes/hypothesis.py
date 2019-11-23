from helios.chains.hypothesis import HypothesisFullChain
from helios.chains.mainnet import (
    MainnetFullChain,
)
from helios.nodes.full import FullNode


class HypothesisFullNode(FullNode):
    chain_class = HypothesisFullChain



