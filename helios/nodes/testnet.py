from helios.chains.testnet import (
    TestnetFullChain,
)
from helios.nodes.full import FullNode


class TestnetFullNode(FullNode):
    chain_class = TestnetFullChain



