from helios.chains.coro import (
    AsyncChain
)

from lahja import (
    Endpoint
)

from typing import Type, TYPE_CHECKING
from eth_typing import Address
from eth_keys.datatypes import PrivateKey

if TYPE_CHECKING:
    from .personal import Personal
    from helios.rpc.main import RPCContext

class RPCModule:
    _chain: AsyncChain = None
    _chain_class: Type[AsyncChain] = None
    personal_module: "Personal" = None
    rpc_context: "RPCContext" = None


    def __init__(self, chain: AsyncChain, event_bus: Endpoint, rpc_context: "RPCContext", chain_class: Type[AsyncChain] = None, personal_module: "Personal" = None) -> None:
        self._chain = chain
        self._chain_class: Type[AsyncChain] = chain_class
        self._event_bus = event_bus
        self.personal_module = personal_module
        self.rpc_context = rpc_context

    def set_chain(self, chain: AsyncChain) -> None:
        self._chain = chain

    def get_new_chain(self, chain_address: Address = None, private_key: PrivateKey = None) -> AsyncChain:
        if chain_address is None:
            return self._chain_class(self._chain.db, wallet_address=self._chain.wallet_address, private_key = private_key)
        else:
            return self._chain_class(self._chain.db, wallet_address=chain_address, private_key = private_key)


