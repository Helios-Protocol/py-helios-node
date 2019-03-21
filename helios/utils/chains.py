import argparse
import os
from pathlib import Path
from typing import (
    Iterable,
    Tuple,
    Union,
)

from eth_utils import (
    decode_hex,
    to_dict,
)

from eth_keys import keys
from eth_keys.datatypes import PrivateKey

from hvm.chains.mainnet import (
    MAINNET_NETWORK_ID,
)

from hp2p.constants import DEFAULT_MAX_PEERS

from helios.constants import SYNC_LIGHT


DEFAULT_DATA_DIRS = {
    MAINNET_NETWORK_ID: 'mainnet',
}


#
# Filesystem path utils
#


def get_local_data_dir(chain_name: str, helios_root_dir: Path) -> Path:
    """
    Returns the base directory path where data for a given chain will be stored.
    """
    try:
        return Path(os.environ['HELIOS_DATA_DIR'])
    except KeyError:
        return helios_root_dir / chain_name


def get_data_dir_for_network_id(network_id: int, helios_root_dir: Path) -> Path:
    """
    Returns the data directory for the chain associated with the given network
    id.  If the network id is unknown, raises a KeyError.
    """
    try:
        return get_local_data_dir(DEFAULT_DATA_DIRS[network_id], helios_root_dir)
    except KeyError:
        raise KeyError("Unknown network id: `{0}`".format(network_id))


LOG_DIRNAME = 'logs'
LOG_FILENAME = 'helios.log'


def get_logfile_path(data_dir: Path) -> Path:
    """
    Return the path to the log file.
    """
    return data_dir / LOG_DIRNAME / LOG_FILENAME


NODEKEY_FILENAME = 'nodekey'


def get_nodekey_path(data_dir: Path) -> Path:
    """
    Returns the path to the private key used for devp2p connections.
    """
    return Path(os.environ.get(
        'HELIOS_NODEKEY',
        str(data_dir / NODEKEY_FILENAME),
    ))

LOCAL_PEER_POOL_FILENAME = 'local_peer_pool'


def get_local_peer_pool_path(data_dir: Path) -> Path:
    """
    Returns the path to the private key used for devp2p connections.
    """
    return Path(os.environ.get(
        'LOCAL_PEER_POOL',
        str(data_dir / LOCAL_PEER_POOL_FILENAME),
    ))


DATABASE_SOCKET_FILENAME = 'db.ipc'


def get_database_socket_path(data_dir: Path) -> Path:
    """
    Returns the path to the private key used for devp2p connections.

    We're still returning 'str' here on ipc-related path because an issue with
    multi-processing not being able to interpret 'Path' objects correctly.
    """
    return Path(os.environ.get(
        'HELIOS_DATABASE_IPC',
        data_dir / DATABASE_SOCKET_FILENAME,
    ))




def get_chain_socket_path(data_dir: Path, instance = 0) -> Path:
    """
    Returns the path to the private key used for devp2p connections.

    We're still returning 'str' here on ipc-related path because an issue with
    multi-processing not being able to interpret 'Path' objects correctly.
    """
    filename = "chain_instance_{}.ipc".format(instance)
    return Path(os.environ.get(
        'HELIOS_CHAIN_INSTANCE_{}_IPC'.format(instance),
        data_dir / filename,
    ))


JSONRPC_SOCKET_FILENAME = 'jsonrpc.ipc'


def get_jsonrpc_socket_path(data_dir: Path) -> Path:
    """
    Returns the path to the ipc socket for the JSON-RPC server.

    We're still returning 'str' here on ipc-related path because an issue with
    multi-processing not being able to interpret 'Path' objects correctly.
    """
    return Path(os.environ.get(
        'HELIOS_JSONRPC_IPC',
        data_dir / JSONRPC_SOCKET_FILENAME,
    ))


#
# Nodekey loading
#
def load_nodekey(nodekey_path: Path) -> PrivateKey:
    with nodekey_path.open('rb') as nodekey_file:
        nodekey_raw = nodekey_file.read()
    nodekey = keys.PrivateKey(nodekey_raw)
    return nodekey


@to_dict
def construct_chain_config_params(
        args: argparse.Namespace) -> Iterable[Tuple[str, Union[int, str, Tuple[str, ...]]]]:
    """
    Helper function for constructing the kwargs to initialize a ChainConfig object.
    """
    yield 'network_id', args.network_id
    yield 'use_discv5', args.discv5

    if args.helios_root_dir is not None:
        yield 'helios_root_dir', args.helios_root_dir

    if args.data_dir is not None:
        yield 'data_dir', args.data_dir

    if args.node_type is not None:
        yield 'node_type', args.node_type

    if args.nodekey_path and args.nodekey:
        raise ValueError("Cannot provide both nodekey_path and nodekey")
    elif args.nodekey_path is not None:
        yield 'nodekey_path', args.nodekey_path
    elif args.nodekey is not None:
        yield 'nodekey', decode_hex(args.nodekey)

    if args.sync_mode is not None:
        yield 'sync_mode', args.sync_mode

    if args.max_peers is not None:
        yield 'max_peers', args.max_peers
    else:
        yield 'max_peers', _default_max_peers(args.sync_mode)

    if args.port is not None:
        yield 'port', args.port

    if args.rpc_port is not None:
        yield 'rpc_port', args.rpc_port

    if args.keystore_path is not None:
        yield 'keystore_path', args.keystore_path

    if args.network_startup_node is not None:
        yield 'network_startup_node', args.network_startup_node

    if args.disable_smart_contract_chain_manager is not None:
        yield 'disable_smart_contract_chain_manager', args.disable_smart_contract_chain_manager

    if args.preferred_nodes is None:
        yield 'preferred_nodes', tuple()
    else:
        yield 'preferred_nodes', tuple(args.preferred_nodes)

    if args.keystore_password is not None:
        yield 'keystore_password', args.keystore_password


def _default_max_peers(sync_mode: str) -> int:
    if sync_mode == SYNC_LIGHT:
        return DEFAULT_MAX_PEERS // 2
    else:
        return DEFAULT_MAX_PEERS
