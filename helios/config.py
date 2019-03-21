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
)
from helios.utils.chains import (
    construct_chain_config_params,
    get_data_dir_for_network_id,
    get_database_socket_path,
    get_jsonrpc_socket_path,
    get_logfile_path,
    get_nodekey_path,
    load_nodekey,
    get_local_peer_pool_path,
    get_chain_socket_path)
from helios.utils.filesystem import (
    PidFile,
)
from helios.utils.xdg import (
    get_xdg_helios_root,
)

from helios.dev_tools import load_local_nodes

from helios.utils.keybox import get_primary_node_private_helios_key

import eth_keyfile

if TYPE_CHECKING:
    # avoid circular import
    from helios.nodes.base import Node  # noqa: F401

DATABASE_DIR_NAME = 'chain'

try:
    from .helios_config import KEYSTORE_FILENAME_TO_USE
except ModuleNotFoundError:
    print("Keystore configuration file required. Please use the template to create a helios_config.py file. See our github for more details.")


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
    _local_peer_pool_path = None


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
                 node_type: int=1,
                 network_startup_node: bool= False,
                 disable_smart_contract_chain_manager: bool= False,
                 keystore_path: str= None,
                 keystore_password: str=None,
                 ) -> None:

        if keystore_password is not None:
            self.keystore_password = bytes(keystore_password, 'UTF-8')
        else:
            self.keystore_password = None

        self.keystore_path = keystore_path
        self.network_startup_node = network_startup_node
        self._disable_smart_contract_chain_manager = disable_smart_contract_chain_manager
        self.network_id = network_id
        self.max_peers = max_peers
        self.sync_mode = sync_mode
        self.port = port
        self.rpc_port = rpc_port
        self.use_discv5 = use_discv5

        # TODO: disable this on release
        self.report_memory_usage = False
        self.memory_usage_report_interval = 10

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

        self._num_chain_processes = 2

    @property
    def num_chain_processes(self):
        #TODO: determine by number of threads
        return self._num_chain_processes

    @num_chain_processes.setter
    def num_chain_processes(self, val):
        self._num_chain_processes = val

    @property
    def is_dev_test_node(self):
        if "INSTANCE_NUMBER" in os.environ:
            return True
        else:
            return False

    @property
    def preferred_nodes(self):
        if self.is_dev_test_node and (self._preferred_nodes is None or len(self._preferred_nodes) == 0):
            try:
                self._preferred_nodes = tuple(load_local_nodes(self.local_peer_pool_path, self.nodekey))
            except FileNotFoundError:
                self._preferred_nodes = ()
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
            if self.is_dev_test_node:
                self.save_node_address_to_local_peer_pool_file()

                if len(self.preferred_nodes) == 0:
                    self._bootstrap_nodes = tuple(
                        KademliaNode.from_uri(enode) for enode in MAINNET_BOOTNODES
                    )
                else:
                    saved_bootstrap_nodes = tuple(load_local_nodes(self.local_peer_pool_path))

                    #assume instance 0 is the bootstrap node for dev testing
                    bootstrap_node = None
                    for loop_bootstrap_node in saved_bootstrap_nodes:
                        if loop_bootstrap_node.address.tcp_port == 30303:
                            bootstrap_node = loop_bootstrap_node

                    if bootstrap_node is not None and (bootstrap_node.pubkey != self.nodekey_public):
                        self._bootstrap_nodes = (bootstrap_node,)
                    else:
                        self._bootstrap_nodes = ()

            else:
                if self.network_id == MAINNET_NETWORK_ID:
                   self._bootstrap_nodes = tuple(
                       KademliaNode.from_uri(enode) for enode in MAINNET_BOOTNODES
                   )
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
        if self.is_dev_test_node:
            return False
        else:
            return True


    @property
    def node_private_helios_key(self):
        if self._node_private_helios_key is None:
            # if self.is_dev_test_node:
            #     if "INSTANCE_NUMBER" in os.environ:
            #         self._node_private_helios_key = get_primary_node_private_helios_key(int(os.environ["INSTANCE_NUMBER"]))
            #
            # else:

            if (self.keystore_path is None and KEYSTORE_FILENAME_TO_USE is None) or self.keystore_password is None:
                raise ValueError("You must provide a keystore file containing a private key for this node, and a password to open it.")
            else:
                try:
                    if self.keystore_path is not None:
                        self._node_private_helios_key = keys.PrivateKey(eth_keyfile.extract_key_from_keyfile(self.keystore_path, self.keystore_password))
                    else:
                        absolute_dir = os.path.dirname(os.path.realpath(__file__))
                        absolute_keystore_path = absolute_dir + '/keystore/'
                        self._node_private_helios_key = keys.PrivateKey(eth_keyfile.extract_key_from_keyfile(absolute_keystore_path + KEYSTORE_FILENAME_TO_USE, self.keystore_password))
                except ValueError:
                    raise ValueError(
                        "An error occured when decoding your keyfile. This can be caused by an incorrect password, or damaged keyfile.")

        return self._node_private_helios_key

    @property
    def node_wallet_address(self):
        if self._node_wallet_address is None:
            if self.node_private_helios_key is None:
                raise ValueError("You must provide a keystore file containing a private key for this node, and a password to open it.")
            else:
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


    def get_chain_ipc_path(self, instance = 0) -> Path:
        """
        Path for the database IPC socket connection.
        """
        return get_chain_socket_path(self.data_dir, instance)



    @property
    def jsonrpc_ipc_path(self) -> Path:
        """
        Path for the JSON-RPC server IPC socket.
        """
        return get_jsonrpc_socket_path(self.data_dir)

    @property
    def local_peer_pool_path(self) -> Path:
        if self._local_peer_pool_path is None:
            self._local_peer_pool_path = get_local_peer_pool_path(self.helios_root_dir)
        return self._local_peer_pool_path


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
            with path.open('r') as peer_file:
                existing_peers_raw = peer_file.read()
                existing_peers = json.loads(existing_peers_raw)

            # only allow one per port. Delete any conflicts.
            for j in range(len(existing_peers)-1, -1, -1):
                if existing_peers[j][2] == udp_port or existing_peers[j][3] == tcp_port:
                    existing_peers.pop(j)

            #append the new one
            if new_peer not in existing_peers:
                existing_peers.append(new_peer)

        except FileNotFoundError:
            #No local peers exist yet. lets start a new list.
            existing_peers = []
            existing_peers.append(new_peer)

        #then save
        with path.open('w') as peer_file:
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
