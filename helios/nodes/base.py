from abc import abstractmethod
from pathlib import Path
from multiprocessing.managers import (
    BaseManager,
)
from typing import (
    Type,
    List,
)

from helios.utils.chain_proxy import create_chain_manager
from hvm.chains.base import (
    BaseChain,
)
from helios.chains.coro import AsyncChain

from hp2p.peer import BasePeerPool
from hp2p.service import (
    BaseService,
)

from helios.config import (
    ChainConfig,
)
from helios.extensibility import (
    PluginManager,
)
from helios.extensibility.events import (
    ResourceAvailableEvent
)
from helios.utils.db_proxy import (
    create_db_manager
)
from eth_typing import Address

from eth_keys.datatypes import PrivateKey


class Node(BaseService):
    """
    Create usable nodes by adding subclasses that define the following
    unset attributes.
    """
    chain_class: Type[BaseChain] = None
    _chain_managers: List[BaseManager] = []

    def __init__(self, plugin_manager: PluginManager, chain_config: ChainConfig) -> None:
        super().__init__()
        self.chain_config: ChainConfig = chain_config
        self.private_helios_key = chain_config.node_private_helios_key
        self.wallet_address = chain_config.node_wallet_address
        self._plugin_manager = plugin_manager
        self._db_manager = create_db_manager(chain_config.database_ipc_path)
        self._db_manager.connect()  # type: ignore

        for i in range(chain_config.num_chain_processes):
            chain_manager = create_chain_manager(chain_config.get_chain_ipc_path(i))
            chain_manager.connect()
            self._chain_managers.append(chain_manager)

        self._chain_head_db = self._db_manager.get_chain_head_db()  # type: ignore
        self._jsonrpc_ipc_path: Path = chain_config.jsonrpc_ipc_path

    @abstractmethod
    def get_chain(self) -> AsyncChain:
        raise NotImplementedError("Node classes must implement this method")

    @abstractmethod
    def get_new_chain(self, chain_address: Address=None, private_key:PrivateKey = None) -> AsyncChain:
        raise NotImplementedError("Node classes must implement this method")

    @abstractmethod
    def get_new_private_chain(self, chain_address: Address = None) -> AsyncChain:
        raise NotImplementedError("Node classes must implement this method")

    @abstractmethod
    def get_peer_pool(self) -> BasePeerPool:
        """
        Return the PeerPool instance of the node
        """
        raise NotImplementedError("Node classes must implement this method")

    @abstractmethod
    def get_p2p_server(self) -> BaseService:
        """
        This is the main service that will be run, when calling :meth:`run`.
        It's typically responsible for syncing the chain, with peer connections.
        """
        raise NotImplementedError("Node classes must implement this method")

    @property
    def db_manager(self) -> BaseManager:
        return self._db_manager

    @property
    def chain_managers(self) -> List[BaseManager]:
        return self._chain_managers

    @property
    def chain_head_db(self):
        return self._chain_head_db

    def notify_resource_available(self) -> None:

        # We currently need this to give plugins the chance to start as soon
        # as the `PeerPool` is available. In the long term, the peer pool may become
        # a plugin itself and we can get rid of this.
        peer_pool = self.get_peer_pool()
        self._plugin_manager.broadcast(ResourceAvailableEvent(
            resource=(peer_pool, self.cancel_token),
            resource_type=type(peer_pool)
        ))

        # This broadcasts the *local* chain, which is suited for tasks that aren't blocking
        # for too long. There may be value in also broadcasting the proxied chain.
        self._plugin_manager.broadcast(ResourceAvailableEvent(
            resource=self.get_chain(),
            resource_type=BaseChain
        ))

    async def _run(self) -> None:
        await self.get_p2p_server().run()
