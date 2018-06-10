import json
from evm.chains.base import BaseChain
from p2p.peer import (
    PreferredNodePeerPool,
    HardCodedNodesPeerPool,
    LocalNodesPeerPool,
)
from p2p.server import Server
from p2p.service import BaseService

from trinity.nodes.base import Node
from trinity.config import (
    ChainConfig,
)


class FullNode(Node):
    _chain: BaseChain = None
    _p2p_server: BaseService = None

    def __init__(self, chain_config: ChainConfig) -> None:
        super().__init__(chain_config)
        
        self._bootstrap_nodes = chain_config.bootstrap_nodes
        self._network_id = chain_config.network_id
        self._node_key = chain_config.nodekey
        self._node_port = chain_config.port
        self._max_peers = chain_config.max_peers
        
        self.save_node_address_to_local_peer_pool_file()

    def get_chain(self):
        if self._chain is None:
            self._chain = self.chain_class(self.db_manager.get_db(), self.wallet_address)

        return self._chain

    #save as [public_key,ip,udp_port,tcp_port]
    def save_node_address_to_local_peer_pool_file(self):
        #path, node_key, ip, udp_port, tcp_port
        path = self.chain_config.local_peer_pool_path
        node_key = self._node_key
        ip = '127.0.0.1'
        udp_port = self._node_port
        tcp_port = self._node_port
        
        public_key_hex = node_key.public_key.to_hex()
        
        new_peer = [public_key_hex, ip, udp_port, tcp_port]
        
        #load existing pool
        try:
            with open(path, 'r') as peer_file:
                existing_peers_raw = peer_file.read()
                existing_peers = json.loads(existing_peers_raw)
            #append the new one
            if not new_peer in existing_peers:
                existing_peers.append(new_peer)
                
        except FileNotFoundError:
            #No local peers exist yet. lets start a new list.
            existing_peers = []
            existing_peers.append(new_peer)
        
            
        #then save
        with open(path, 'w') as peer_file:
            peer_file.write(json.dumps(existing_peers))
            
            
    def get_p2p_server(self) -> BaseService:
        
        if self._p2p_server is None:
            manager = self.db_manager
            #for development and testing we will use a list of hardcoded peer nodes
            self._p2p_server = Server(
                self._node_key,
                self._node_port,
                manager.get_chain(),  # type: ignore
                manager.get_chaindb(),  # type: ignore
                manager.get_db(),  # type: ignore
                self._network_id,
                max_peers=self._max_peers,
                peer_pool_class=LocalNodesPeerPool,
                bootstrap_nodes=self._bootstrap_nodes,
                token=self.cancel_token,
            )
#            self._p2p_server = Server(
#                self._node_key,
#                self._node_port,
#                manager.get_chain(),  # type: ignore
#                manager.get_chaindb(),  # type: ignore
#                manager.get_db(),  # type: ignore
#                self._network_id,
#                max_peers=self._max_peers,
#                peer_pool_class=PreferredNodePeerPool,
#                bootstrap_nodes=self._bootstrap_nodes,
#                token=self.cancel_token,
#            )
        return self._p2p_server
