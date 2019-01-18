import asyncio

from cancel_token import OperationCancelled

from helios.config import ChainConfig
from helios.db.chain_head import AsyncChainHeadDB
from helios.db.consensus import AsyncConsensusDB
from helios.nodes.full import FullNode
from helios.protocol.common.datastructures import SyncParameters
from hvm import MainnetChain
from hvm.db.backends.level import LevelDB
from hvm.db.backends.memory import MemoryDB
from hvm.db.atomic import AtomicDB

from helios.db.base import AsyncBaseDB
from helios.db.chain import AsyncChainDB
from hvm.chains.mainnet import (
    MAINNET_GENESIS_PARAMS,
    MAINNET_GENESIS_STATE,
    GENESIS_PRIVATE_KEY,
    MAINNET_NETWORK_ID,
)

from helios.dev_tools import create_dev_test_random_blockchain_database, \
    create_blockchain_database_for_exceeding_tpc_cap


async def connect_to_peers_loop(peer_pool, nodes):
    """Loop forever trying to connect to one of the given nodes if the pool is not yet full."""
    while peer_pool.is_operational:
        try:
            if not peer_pool.is_full:
                await peer_pool.connect_to_nodes(nodes)
            await peer_pool.wait(asyncio.sleep(2))
        except OperationCancelled:
            break


def async_passthrough(base_name):
    coro_name = 'coro_{0}'.format(base_name)

    async def passthrough_method(self, *args, **kwargs):
        return getattr(self, base_name)(*args, **kwargs)
    passthrough_method.__name__ = coro_name
    return passthrough_method


class FakeAsyncAtomicDB(AtomicDB, AsyncBaseDB):
    coro_set = async_passthrough('set')
    coro_exists = async_passthrough('exists')


class FakeAsyncMemoryDB(MemoryDB, AsyncBaseDB):
    coro_set = async_passthrough('set')
    coro_exists = async_passthrough('exists')


class FakeAsyncLevelDB(LevelDB, AsyncBaseDB):
    coro_set = async_passthrough('set')
    coro_exists = async_passthrough('exists')

class FakeAsyncChainDB(AsyncChainDB):
    coro_persist_block = async_passthrough('persist_block')
    coro_persist_uncles = async_passthrough('persist_uncles')
    coro_persist_trie_data_dict = async_passthrough('persist_trie_data_dict')
    coro_get = async_passthrough('get')
    coro_get_block_transactions = async_passthrough('get_block_transactions')
    coro_get_block_uncles = async_passthrough('get_block_uncles')
    coro_get_receipts = async_passthrough('get_receipts')
    coro_get_all_block_hashes_on_chain_by_head_block_hash = async_passthrough('get_all_block_hashes_on_chain_by_head_block_hash')
    coro_get_all_blocks_on_chain_by_head_block_hash = async_passthrough('get_all_blocks_on_chain_by_head_block_hash')
    coro_get_block_by_hash= async_passthrough('get_block_by_hash')

class FakeAsyncChainHeadDB(AsyncChainHeadDB):
    coro_get_dense_historical_root_hashes = async_passthrough('get_dense_historical_root_hashes')
    coro_get_head_block_hashes_list = async_passthrough('get_head_block_hashes_list')
    coro_get_historical_root_hash = async_passthrough('get_historical_root_hash')
    coro_get_historical_root_hashes = async_passthrough('get_historical_root_hashes')
    coro_load_chronological_block_window = async_passthrough('load_chronological_block_window')
    coro_get_head_block_hashes_by_idx_list = async_passthrough('get_head_block_hashes_by_idx_list')
    coro_initialize_historical_root_hashes = async_passthrough('initialize_historical_root_hashes')



class FakeAsyncConsensusDB(AsyncConsensusDB):
    pass


async def coro_import_block(chain, block, perform_validation=True):
    # Be nice and yield control to give other coroutines a chance to run before us as
    # importing a block is a very expensive operation.
    await asyncio.sleep(0)
    return chain.import_block(block, perform_validation=perform_validation)





class FakeAsyncMainnetChain(MainnetChain):
    chaindb_class = FakeAsyncChainDB
    coro_import_block = coro_import_block
    coro_validate_chain = async_passthrough('validate_chain')
    coro_validate_receipt = async_passthrough('validate_receipt')
    coro_get_mature_stake = async_passthrough('get_mature_stake')
    coro_get_local_tpc_cap = async_passthrough('get_local_tpc_cap')


class FakeMainnetFullNode():
    chain_class = FakeAsyncMainnetChain
    chain = None

    def __init__(self, base_db, priv_key):
        self.base_db = base_db
        self.priv_key = priv_key

    def get_chain(self):
        if self.chain is None:
            self._chain = self.chain_class(self.base_db, self.priv_key.public_key.to_canonical_address())  # type: ignore

        return self._chain

    def get_new_chain(self, chain_address=None, private_key = None):
        if chain_address is None:
            chain_address = self.priv_key.public_key.to_canonical_address()

        return self.chain_class(self.base_db, chain_address, private_key)

    def get_new_private_chain(self, chain_address= None):
        if chain_address is None:
            chain_address = self.priv_key.public_key.to_canonical_address()

        return self.get_new_chain(chain_address = chain_address, private_key = self.priv_key)


def get_fresh_db():
    testdb1 = MemoryDB()
    MainnetChain.from_genesis(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)
    return testdb1

def get_random_blockchain_db():
    testdb1 = MemoryDB()
    create_dev_test_random_blockchain_database(testdb1)
    return testdb1

def get_random_long_time_blockchain_db(length_in_centiseconds = 50):
    testdb1 = MemoryDB()
    create_blockchain_database_for_exceeding_tpc_cap(testdb1,1,length_in_centiseconds, use_real_genesis = True)
    return testdb1




class MockConsensusService():

    def __init__(self, sync_parameters = None, block_conflict_choices = None):
        self.sync_parameters = sync_parameters
        self.coro_is_ready = asyncio.Event()
        self.coro_min_gas_system_ready = asyncio.Event()

        self.coro_is_ready.set()
        self.coro_min_gas_system_ready.set()

        self.block_conflict_choices = block_conflict_choices

    async def get_blockchain_sync_parameters(self):
        return self.sync_parameters

    async def get_correct_block_conflict_choice_where_we_differ_from_consensus(self):
        return self.block_conflict_choices