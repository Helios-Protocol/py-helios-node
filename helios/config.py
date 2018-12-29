import argparse
from contextlib import contextmanager
from pathlib import Path
import os
import json

from typing import (
    TYPE_CHECKING,
    Tuple,
    Type,
    Union,
)

from eth_keys import keys
from eth_keys.datatypes import PrivateKey
from hvm.chains.mainnet import (
    MAINNET_NETWORK_ID,
)

from hp2p.kademlia import Node as KademliaNode


from helios.constants import (
    SYNC_FULL,
    SYNC_LIGHT,
)
from hp2p.constants import (
    MAINNET_BOOTNODES,
    LOCAL_PEER_POOL_PATH,
)
from helios.utils.chains import (
    construct_chain_config_params,
    get_data_dir_for_network_id,
    get_database_socket_path,
    get_jsonrpc_socket_path,
    get_logfile_path,
    get_nodekey_path,
    load_nodekey,
)
from helios.utils.filesystem import (
    PidFile,
)
from helios.utils.xdg import (
    get_xdg_helios_root,
)

from helios.dev_tools import load_local_nodes

from helios.utils.keybox import get_primary_node_private_helios_key

if TYPE_CHECKING:
    # avoid circular import
    from helios.nodes.base import Node  # noqa: F401

DATABASE_DIR_NAME = 'chain'


class ChainConfig:
    _helios_root_dir: Path = None
    _data_dir: Path = None
    _nodekey_path: Path = None
    _logfile_path: Path = None
    _nodekey = None
    _nodekey_public = None
    _network_id: int = None
    _node_private_helios_key = None
    _node_wallet_address = None
    _node_type = 1

    port: int = None
    rpc_port: int = None
    _preferred_nodes: Tuple[KademliaNode, ...] = None

    _bootstrap_nodes: Tuple[KademliaNode, ...] = None

    def __init__(self,
                 network_id: int,
                 max_peers: int=25,
                 helios_root_dir: str=None,
                 data_dir: str=None,
                 nodekey_path: str=None,
                 logfile_path: str=None,
                 nodekey: PrivateKey=None,
                 sync_mode: str=SYNC_FULL,
                 port: int=30303,
                 rpc_port: int = 30304,
                 use_discv5: bool = False,
                 preferred_nodes: Tuple[KademliaNode, ...]=None,
                 bootstrap_nodes: Tuple[KademliaNode, ...]=None,
                 node_type=1,
                 network_startup_node = False,
                 disable_smart_contract_chain_manager = False,
                 ) -> None:
        self.network_startup_node = network_startup_node
        self._disable_smart_contract_chain_manager = disable_smart_contract_chain_manager
        self.network_id = network_id
        self.max_peers = max_peers
        self.sync_mode = sync_mode
        self.port = port
        self.rpc_port = rpc_port
        self.use_discv5 = use_discv5

        if self.network_startup_node:
            #network startup nodes must be bootnodes.
            self.node_type = 4
        else:
            self.node_type = int(node_type)

        if helios_root_dir is not None:
            self.helios_root_dir = helios_root_dir

        self._preferred_nodes = preferred_nodes

        self._bootstrap_nodes = bootstrap_nodes

        if data_dir is not None:
            self.data_dir = data_dir

        if nodekey is not None and nodekey_path is not None:
            raise ValueError("It is invalid to provide both a `nodekey` and a `nodekey_path`")
        elif nodekey_path is not None:
            self.nodekey_path = nodekey_path
        elif nodekey is not None:
            self.nodekey = nodekey

        if logfile_path is not None:
            self.logfile_path = logfile_path

    @property
    def preferred_nodes(self):
        if self._preferred_nodes is None or len(self._preferred_nodes) == 0:
            self._preferred_nodes = tuple(load_local_nodes(self.nodekey))
        return self._preferred_nodes

    @property
    def disable_smart_contract_chain_manager(self):
        if self._disable_smart_contract_chain_manager:
            return True
        elif self.node_type == 2: #micronode
            return True
        else:
            return False

    @property
    def bootstrap_nodes(self):
        if self._bootstrap_nodes is None or len(self._bootstrap_nodes) == 0:
            #make sure we save our node to the file before loading it. This will create the file if it doesnt exist.
            self.save_node_address_to_local_peer_pool_file()

            if len(self.preferred_nodes) == 0:
                self._bootstrap_nodes = tuple(
                    KademliaNode.from_uri(enode) for enode in MAINNET_BOOTNODES
                )
            else:
                bootstrap_nodes = tuple(load_local_nodes())
                if bootstrap_nodes[0].pubkey != self.nodekey_public:
                    self._bootstrap_nodes = (bootstrap_nodes[0],)
                else:
                    self._bootstrap_nodes = ()

#             if self.network_id == MAINNET_NETWORK_ID:
#                    self._bootstrap_nodes = tuple(
#                        KademliaNode.from_uri(enode) for enode in MAINNET_BOOTNODES
#                    )

        return self._bootstrap_nodes

    @property
    def is_main_instance(self):
        if self.network_startup_node:
            return True
        elif "INSTANCE_NUMBER" in os.environ:
            return int(os.environ["INSTANCE_NUMBER"]) == 0
        else:
            return True

    @property
    def do_upnp(self):
        #TODO: TESTING
        return False
        return self.is_main_instance

    #todo: add encrypted keyfile usage instead of this
    @property
    def node_private_helios_key(self):
        if self._node_private_helios_key is None:
            if "INSTANCE_NUMBER" in os.environ:
                self._node_private_helios_key = get_primary_node_private_helios_key(int(os.environ["INSTANCE_NUMBER"]))
            else:
                self._node_private_helios_key = get_primary_node_private_helios_key()
        return self._node_private_helios_key

    @property
    def node_wallet_address(self):
        if self._node_wallet_address is None:
            self._node_wallet_address = self.node_private_helios_key.public_key.to_canonical_address()
        return self._node_wallet_address

    #0 is master, 1 is fullnode, 2 is micronode, 4 is bootstrap_node
    @property
    def node_type(self):
        return self._node_type

    @node_type.setter
    def node_type(self, val):
        self._node_type = val

    @property
    def logfile_path(self) -> Path:
        """
        Return the path to the log file.
        """
        if self._logfile_path is not None:
            return self._logfile_path
        else:
            return get_logfile_path(self.data_dir)

    @logfile_path.setter
    def logfile_path(self, value: Path) -> None:
        self._logfile_path = value

    @property
    def logdir_path(self) -> Path:
        """
        Return the path of the directory where all log files are stored.
        """
        return self.logfile_path.parent

    @property
    def helios_root_dir(self) -> Path:
        """
        The helios_root_dir is the base directory that all helios data is
        stored under.

        The default ``data_dir`` path will be resolved relative to this
        directory.
        """
        if self._helios_root_dir is not None:
            return self._helios_root_dir
        else:
            return get_xdg_helios_root()

    @helios_root_dir.setter
    def helios_root_dir(self, value: str) -> None:
        self._helios_root_dir = Path(value).resolve()

    @property
    def data_dir(self) -> Path:
        """
        The data_dir is the base directory that all chain specific information
        for a given chain is stored.

        All defaults for chain directories are resolved relative to this
        directory.
        """
        if self._data_dir is not None:
            return self._data_dir
        else:
            return get_data_dir_for_network_id(self.network_id, self.helios_root_dir)

    @data_dir.setter
    def data_dir(self, value: str) -> None:
        self._data_dir = Path(value).resolve()

    @property
    def database_dir(self) -> Path:
        """
        Path where the chain database will be stored.

        This is resolved relative to the ``data_dir``
        """
        if self.sync_mode == SYNC_FULL:
            return self.data_dir / DATABASE_DIR_NAME / "full"
        elif self.sync_mode == SYNC_LIGHT:
            return self.data_dir / DATABASE_DIR_NAME / "light"
        else:
            raise ValueError("Unknown sync mode: {}".format(self.sync_mode))

    @property
    def database_ipc_path(self) -> Path:
        """
        Path for the database IPC socket connection.
        """
        return get_database_socket_path(self.data_dir)

    @property
    def jsonrpc_ipc_path(self) -> Path:
        """
        Path for the JSON-RPC server IPC socket.
        """
        return get_jsonrpc_socket_path(self.data_dir)

    @property
    def local_peer_pool_path(self):
        return LOCAL_PEER_POOL_PATH

    #save as [public_key,ip,udp_port,tcp_port]
    def save_node_address_to_local_peer_pool_file(self):
        #path, node_key, ip, udp_port, tcp_port
        path = self.local_peer_pool_path
        node_key = self.nodekey

        ip = '127.0.0.1'
        udp_port = self.port
        tcp_port = self.port

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


    @property
    def nodekey_path(self) -> Path:
        """
        Path where the nodekey is stored
        """
        if self._nodekey_path is None:
            if self._nodekey is not None:
                return None
            else:
                return get_nodekey_path(self.data_dir)
        else:
            return self._nodekey_path

    @nodekey_path.setter
    def nodekey_path(self, value: str) -> None:
        self._nodekey_path = Path(value).resolve()

    @property
    def nodekey_public(self):
        if self._nodekey_public is None:
            private_key = self.nodekey
            self._nodekey_public = private_key.public_key

        return self._nodekey_public

    @property
    def nodekey(self) -> PrivateKey:
        if self._nodekey is None:
            try:
                return load_nodekey(self.nodekey_path)
            except FileNotFoundError:
                # no file at the nodekey_path so we have a null nodekey
                return None
        else:
            if isinstance(self._nodekey, bytes):
                return keys.PrivateKey(self._nodekey)
            elif isinstance(self._nodekey, PrivateKey):
                return self._nodekey
            return self._nodekey

    @nodekey.setter
    def nodekey(self, value: Union[bytes, PrivateKey]) -> None:
        if isinstance(value, bytes):
            self._nodekey = keys.PrivateKey(value)
        elif isinstance(value, PrivateKey):
            self._nodekey = value
        else:
            raise TypeError(
                "Nodekey must either be a raw byte-string or an eth_keys "
                "`PrivateKey` instance"
            )

    @classmethod
    def from_parser_args(cls, parser_args: argparse.Namespace) -> 'ChainConfig':
        """
        Helper function for initializing from the namespace object produced by
        an ``argparse.ArgumentParser``
        """
        constructor_kwargs = construct_chain_config_params(parser_args)
        return cls(**constructor_kwargs)

    @property
    def node_class(self) -> Type['Node']:
        from helios.nodes.mainnet import (
            MainnetFullNode,
            #MainnetLightNode,
        )
        if self.sync_mode == SYNC_LIGHT:
            if self.network_id == MAINNET_NETWORK_ID:
                #return MainnetLightNode
                return False
            else:
                raise NotImplementedError(
                    "Only the mainnet and ropsten chains are currently supported"
                )
        elif self.sync_mode == SYNC_FULL:
            if self.network_id == MAINNET_NETWORK_ID:
                return MainnetFullNode
            else:
                raise NotImplementedError(
                    "Only the mainnet and ropsten chains are currently supported"
                )
        else:
            raise NotImplementedError(
                "Only full and light sync modes are supported"
            )

    @contextmanager
    def process_id_file(self, process_name: str):  # type: ignore
        with PidFile(process_name, self.data_dir):
            yield
