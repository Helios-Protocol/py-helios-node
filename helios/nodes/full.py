import json
from helios.chains.coro import (
    AsyncChain
)

from hp2p.peer import BasePeerPool

from helios.config import ChainConfig
from helios.extensibility import PluginManager
from helios.server import FullServer

from .base import Node

from eth_keys.datatypes import PrivateKey
from eth_typing import Address

class FullNode(Node):
    _chain: AsyncChain = None
    _p2p_server: FullServer = None

    def __init__(self, plugin_manager: PluginManager, chain_config: ChainConfig) -> None:
        super().__init__(plugin_manager, chain_config)
        self._bootstrap_nodes = chain_config.bootstrap_nodes
        self._preferred_nodes = chain_config.preferred_nodes
        self._network_id = chain_config.network_id
        self._node_key = chain_config.nodekey
        self._node_port = chain_config.port
        self._rpc_port = chain_config.rpc_port
        self._max_peers = chain_config.max_peers


        self.notify_resource_available()



    def get_chain(self) -> AsyncChain:
        if self._chain is None:
            self._chain = self.chain_class(self.db_manager.get_db(), self.wallet_address)  # type: ignore

        return self._chain

    def get_new_private_chain(self, chain_address: Address = None) -> AsyncChain:
        '''
        Generates a new chain object that includes the nodes private key. This object can be used to create blocks and
        do other things requiring signing with a private key. It allows the user to set the chain_address to cover
        smart contract chains that differ from the wallet address derived from the private key.
        :param chain_address:
        :return:
        '''
        if chain_address is None:
            chain_address = self.chain_config.node_private_helios_key.public_key.to_canonical_address()

        return self.get_new_chain(chain_address = chain_address,
                                  private_key = self.chain_config.node_private_helios_key)

    def get_new_chain(self, chain_address: Address=None, private_key:PrivateKey = None) -> AsyncChain:
        if chain_address is None:
            chain_address = self.wallet_address
        return self.chain_class(self.db_manager.get_db(), chain_address, private_key)


    def get_p2p_server(self) -> FullServer:
        if self._p2p_server is None:
            manager = self.db_manager
            chain_managers = self.chain_managers
            chains = [manager.get_chain() for manager in chain_managers]
            #TODO: send entire list of chain managers for mutliprocessing
            self._p2p_server = FullServer(
                self,
                chains,  # type: ignore
                manager.get_chaindb(),  # type: ignore
                manager.get_chain_head_db(),
                manager.get_consensus_db(),
                manager.get_db(),  # type: ignore
                self._network_id,
                chain_config = self.chain_config,
                max_peers=self._max_peers,
                bootstrap_nodes=self._bootstrap_nodes,
                preferred_nodes=self._preferred_nodes,
                token=self.cancel_token,
                event_bus=self._plugin_manager.event_bus_endpoint
            )
        return self._p2p_server

    def get_peer_pool(self) -> BasePeerPool:
        return self.get_p2p_server().peer_pool
