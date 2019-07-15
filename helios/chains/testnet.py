from hvm import (
    TestnetChain
)

from helios.chains.coro import AsyncChainMixin


class TestnetFullChain(TestnetChain, AsyncChainMixin):
    pass

