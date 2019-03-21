# Typeshed definitions for multiprocessing.managers is incomplete, so ignore them for now:
# https://github.com/python/typeshed/blob/85a788dbcaa5e9e9a62e55f15d44530cd28ba830/stdlib/3/multiprocessing/managers.pyi#L3
from multiprocessing.managers import (  # type: ignore
    BaseManager,
    BaseProxy,
)
import time
import inspect
import os
import traceback
from types import TracebackType
from typing import (
    Any,
    Callable,
    List,
    Type
)

from hvm import MainnetChain
from hvm.chains.base import (
    BaseChain
)
from hvm.chains.mainnet import (
    MAINNET_GENESIS_PARAMS,
    MAINNET_GENESIS_STATE,
    MAINNET_NETWORK_ID,
    GENESIS_WALLET_ADDRESS,
)

from hvm.db.backends.base import BaseAtomicDB
from hvm.exceptions import CanonicalHeadNotFound

from hp2p import ecies

from helios.exceptions import (
    MissingPath,
)
from helios.config import ChainConfig
from helios.db.base import DBProxy
from helios.db.chain import AsyncChainDB, ChainDBProxy
from helios.db.consensus import AsyncConsensusDB, ConsensusDBProxy
from .base import ChainProxy
from helios.db.chain_head import (
    ChainHeadDBProxy,
    AsyncChainHeadDB,
)
from hvm.constants import TIME_BETWEEN_HEAD_HASH_SAVE

# from helios.db.header import (
#     AsyncHeaderDB,
#     AsyncHeaderDBProxy,
# )
from helios.utils.filesystem import (
    is_under_path,
)
from helios.utils.mp import (
    async_method,
    sync_method,
)

from helios.db.base import AsyncBaseDB

from helios.dev_tools import (
    create_dev_test_random_blockchain_database,
    import_genesis_block,
    create_predefined_blockchain_database,
)


def is_data_dir_initialized(chain_config: ChainConfig) -> bool:
    """
    - base dir exists
    - chain data-dir exists
    - nodekey exists and is non-empty
    - canonical chain head in db
    """
    if not os.path.exists(chain_config.data_dir):
        return False

    if not os.path.exists(chain_config.database_dir):
        return False

    if not chain_config.logfile_path.parent.exists():
        return False
    elif not chain_config.logfile_path.exists():
        return False

    if chain_config.nodekey_path is None:
        # has an explicitely defined nodekey
        pass
    elif not os.path.exists(chain_config.nodekey_path):
        return False

    if chain_config.nodekey is None:
        return False

    return True


def is_database_initialized(chaindb: AsyncChainDB) -> bool:
    try:
        chaindb.get_canonical_head(chain_address= GENESIS_WALLET_ADDRESS)
    except CanonicalHeadNotFound:
        # empty chain database
        return False
    else:
        return True


def initialize_data_dir(chain_config: ChainConfig) -> None:
    should_create_data_dir = (
        not chain_config.data_dir.exists() and
        is_under_path(chain_config.helios_root_dir, chain_config.data_dir)
    )
    if should_create_data_dir:
        chain_config.data_dir.mkdir(parents=True, exist_ok=True)
    elif not chain_config.data_dir.exists():
        # we don't lazily create the base dir for non-default base directories.
        raise MissingPath(
            "The base chain directory provided does not exist: `{0}`".format(
                chain_config.data_dir,
            ),
            chain_config.data_dir
        )

    # Logfile
    should_create_logdir = (
        not chain_config.logdir_path.exists() and
        is_under_path(chain_config.helios_root_dir, chain_config.logdir_path)
    )
    if should_create_logdir:
        chain_config.logdir_path.mkdir(parents=True, exist_ok=True)
        chain_config.logfile_path.touch()
    elif not chain_config.logdir_path.exists():
        # we don't lazily create the base dir for non-default base directories.
        raise MissingPath(
            "The base logging directory provided does not exist: `{0}`".format(
                chain_config.logdir_path,
            ),
            chain_config.logdir_path
        )

    # Chain data-dir
    os.makedirs(chain_config.database_dir, exist_ok=True)

    # Nodekey
    if chain_config.nodekey is None:
        nodekey = ecies.generate_privkey()
        with open(chain_config.nodekey_path, 'wb') as nodekey_file:
            nodekey_file.write(nodekey.to_bytes())


def initialize_database(chain_config: ChainConfig, chaindb: AsyncChainDB) -> None:
    try:
        chaindb.get_canonical_head(chain_address= GENESIS_WALLET_ADDRESS)
    except CanonicalHeadNotFound:
        if chain_config.network_id == MAINNET_NETWORK_ID:
            MainnetChain.from_genesis(chaindb.db, chain_config.node_wallet_address, MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)
        else:
            # TODO: add genesis data to ChainConfig and if it's present, use it
            # here to initialize the chain.
            raise NotImplementedError(
                "Only the mainnet and ropsten chains are currently supported"
            )


class TracebackRecorder:
    """
    Wrap the given instance, delegating all attribute accesses to it but if any method call raises
    an exception it is converted into a ChainedExceptionWithTraceback that uses exception chaining
    in order to retain the traceback that led to the exception in the remote process.
    """

    def __init__(self, obj: Any) -> None:
        self.obj = obj

    def __dir__(self) -> List[str]:
        return dir(self.obj)

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self.obj, name)
        if not inspect.ismethod(attr):
            return attr
        else:
            return record_traceback_on_error(attr)


def record_traceback_on_error(attr: Callable[..., Any]) -> Callable[..., Any]:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return attr(*args, **kwargs)
        except Exception as e:
            # This is a bit of a hack based on https://bugs.python.org/issue13831 to record the
            # original traceback (as a string, which is picklable unlike traceback instances) in
            # the exception that will be sent to the remote process.
            raise ChainedExceptionWithTraceback(e, e.__traceback__)

    return wrapper


class RemoteTraceback(Exception):

    def __init__(self, tb: str) -> None:
        self.tb = tb

    def __str__(self) -> str:
        return self.tb


class ChainedExceptionWithTraceback(Exception):

    def __init__(self, exc: Exception, tb: TracebackType) -> None:
        self.tb = '\n"""\n%s"""' % ''.join(traceback.format_exception(type(exc), exc, tb))
        self.exc = exc

    def __reduce__(self) -> Any:
        return rebuild_exc, (self.exc, self.tb)


def rebuild_exc(exc, tb):  # type: ignore
    exc.__cause__ = RemoteTraceback(tb)
    return exc


def get_chaindb_manager(chain_config: ChainConfig, base_db: BaseAtomicDB) -> BaseManager:
    chaindb = AsyncChainDB(base_db)
    chain_head_db = AsyncChainHeadDB.load_from_saved_root_hash(base_db)

    chain_class: Type[BaseChain]
    if not is_database_initialized(chaindb):
        if 'GENERATE_RANDOM_DATABASE' in os.environ:
            #this is for testing, we neeed to build an initial blockchain database
            #create_dev_test_random_blockchain_database(base_db)
            if "INSTANCE_NUMBER" in os.environ:
                create_predefined_blockchain_database(base_db, instance = int(os.environ["INSTANCE_NUMBER"]))
            else:
                create_predefined_blockchain_database(base_db)
        else:
            initialize_database(chain_config = chain_config, chaindb = chaindb)

    if chain_config.network_id == MAINNET_NETWORK_ID:
        chain_class = MainnetChain
    else:
        raise NotImplementedError(
            "Only the mainnet and ropsten chains are currently supported"
        )


    #chain = chain_class(base_db, chain_config.node_wallet_address, chain_config.node_private_helios_key)  # type: ignore

    consensus_db = AsyncConsensusDB(chaindb)


    class DBManager(BaseManager):
        pass

    # Typeshed definitions for multiprocessing.managers is incomplete, so ignore them for now:
    # https://github.com/python/typeshed/blob/85a788dbcaa5e9e9a62e55f15d44530cd28ba830/stdlib/3/multiprocessing/managers.pyi#L3
    DBManager.register(  # type: ignore
        'get_db', callable=lambda: TracebackRecorder(base_db), proxytype=DBProxy)

    DBManager.register(  # type: ignore
        'get_chaindb',
        callable=lambda: TracebackRecorder(chaindb),
        proxytype=ChainDBProxy,
    )
    # DBManager.register(  # type: ignore
    #     'get_chain', callable=lambda: TracebackRecorder(chain), proxytype=ChainProxy)

    DBManager.register(  # type: ignore
        'get_chain_head_db',
        callable=lambda: TracebackRecorder(chain_head_db),
        proxytype=ChainHeadDBProxy,
    )

    DBManager.register(  # type: ignore
        'get_consensus_db',
        callable=lambda: TracebackRecorder(consensus_db),
        proxytype=ConsensusDBProxy,
    )


    manager = DBManager(address=str(chain_config.database_ipc_path))  # type: ignore
    return manager


def get_chain_manager(chain_config: ChainConfig, base_db: AsyncBaseDB, instance = 0) -> BaseManager:
    # TODO: think about using async chian here. Depends which process we would like the threaded work to happen in.
    # There might be a performance savings by doing the threaded work in this process to avoid one process hop.
    if chain_config.network_id == MAINNET_NETWORK_ID:
        chain_class = MainnetChain
    else:
        raise NotImplementedError(
            "Only the mainnet chain is currently supported"
        )

    chain = chain_class(base_db, chain_config.node_wallet_address, chain_config.node_private_helios_key)  # type: ignore

    class ChainManager(BaseManager):
        pass


    ChainManager.register(  # type: ignore
        'get_chain', callable=lambda: TracebackRecorder(chain), proxytype=ChainProxy)



    manager = ChainManager(address=str(chain_config.get_chain_ipc_path(instance)))  # type: ignore
    return manager


