from helios.chains.coro import (
    AsyncChain
)

from lahja import (
    Endpoint
)

from typing import Type


class RPCModule:
    _chain: AsyncChain = None

    def __init__(self, chain: AsyncChain, event_bus: Endpoint, chain_class: Type[AsyncChain] = None) -> None:
        self._chain = chain
        self._chain_class: Type[AsyncChain] = chain_class
        self._event_bus = event_bus

    def set_chain(self, chain: AsyncChain) -> None:
        self._chain = chain


