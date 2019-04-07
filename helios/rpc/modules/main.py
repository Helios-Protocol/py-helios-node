from helios.chains.coro import (
    AsyncChain
)

from lahja import (
    Endpoint
)

from typing import Type
from eth_typing import Address
from eth_keys.datatypes import PrivateKey

class RPCModule:
    _chain: AsyncChain = None
    _chain_class: Type[AsyncChain] = None

    def __init__(self, chain: AsyncChain, event_bus: Endpoint, chain_class: Type[AsyncChain] = None) -> None:
        self._chain = chain
        self._chain_class: Type[AsyncChain] = chain_class
        self._event_bus = event_bus

    def set_chain(self, chain: AsyncChain) -> None:
        self._chain = chain

    def get_new_chain(self, chain_address: Address = None, private_key: PrivateKey = None) -> AsyncChain:
        if chain_address is None:
            return self._chain_class(self._chain.db, wallet_address=self._chain.wallet_address, private_key = private_key)
        else:
            return self._chain_class(self._chain.db, wallet_address=chain_address, private_key = private_key)


