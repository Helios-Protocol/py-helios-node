import asyncio

import logging

from cancel_token import OperationCancelled

from helios.config import ChainConfig
from helios.db.chain_head import AsyncChainHeadDB
from helios.db.consensus import AsyncConsensusDB
from helios.nodes.full import FullNode
from helios.protocol.common.datastructures import SyncParameters
from hp2p.consensus import Consensus, BlockConflictInfo, BlockConflictChoice
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
    create_blockchain_database_for_exceeding_tpc_cap, create_predefined_blockchain_database
from hvm.exceptions import HeaderNotFound


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
    coro_get_block_by_hash = async_passthrough('get_block_by_hash')
    coro_get_blocks_on_chain = async_passthrough('get_blocks_on_chain')
    coro_load_historical_minimum_gas_price = async_passthrough('load_historical_minimum_gas_price')
    coro_get_canonical_head_hash = async_passthrough('get_canonical_head_hash')
    coro_get_latest_reward_block_number = async_passthrough('get_latest_reward_block_number')
    coro_get_canonical_block_header_by_number = async_passthrough('get_canonical_block_header_by_number')
    coro_load_historical_network_tpc_capability = async_passthrough('load_historical_network_tpc_capability')
    coro_save_historical_minimum_gas_price = async_passthrough('save_historical_minimum_gas_price')
    coro_save_historical_network_tpc_capability = async_passthrough('save_historical_network_tpc_capability')

class FakeAsyncChainHeadDB(AsyncChainHeadDB):
    coro_get_dense_historical_root_hashes = async_passthrough('get_dense_historical_root_hashes')
    coro_get_head_block_hashes_list = async_passthrough('get_head_block_hashes_list')
    coro_get_historical_root_hash = async_passthrough('get_historical_root_hash')
    coro_get_historical_root_hashes = async_passthrough('get_historical_root_hashes')
    coro_load_chronological_block_window = async_passthrough('load_chronological_block_window')
    coro_get_head_block_hashes_by_idx_list = async_passthrough('get_head_block_hashes_by_idx_list')
    coro_initialize_historical_root_hashes = async_passthrough('initialize_historical_root_hashes')



class FakeAsyncConsensusDB(AsyncConsensusDB):
    coro_get_signed_peer_score_string_private_key = async_passthrough('get_signed_peer_score_string_private_key')



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

def get_predefined_blockchain_db(instance_number):
    testdb1 = MemoryDB()
    create_predefined_blockchain_database(testdb1, instance=instance_number)
    return testdb1

class MockConsensusService(Consensus):

    def __init__(self,
                 chain_head_db = None,
                 peer_pool = None,
                 sync_parameters = None,
                 sync_stage_override = None,
                 chain_to_sync_to = None,
                 is_server = False,
    ):
        if chain_head_db is None and peer_pool is None and sync_parameters is None:
            raise Exception("you must define chain_head_db and peer_pool or sync_parameters")

        self._sync_parameters = sync_parameters
        self.coro_is_ready = asyncio.Event()
        self.coro_min_gas_system_ready = asyncio.Event()

        self.coro_is_ready.set()
        self.coro_min_gas_system_ready.set()

        self.chain_head_db = chain_head_db

        self.peer_pool = peer_pool

        self._sync_stage_override = sync_stage_override

        self.chain_to_sync_to = chain_to_sync_to

        self.block_conflicts = set()

        self.is_server = is_server

    def get_chain_head_root_hash_for_peer(self, peer_wallet_address, timestamp):
        return self.chain_to_sync_to.chain_head_db.get_historical_root_hash(timestamp)


    async def coro_get_root_hash_consensus(self, timestamp, local_root_hash_timestamps=None):
        '''
        It will always assume the peer is in consensus and we need to sync to them unless
        they dont have the root hash for the given timestamp.
        :param timestamp:
        :param local_root_hash_timestamps:
        :return:
        '''
        local_root_hash_timestamps_dict = dict(self.local_root_hash_timestamps)
        if self.is_server:
            try:
                return local_root_hash_timestamps_dict[timestamp]
            except KeyError:
                return None

        peer_root_hash = self.chain_to_sync_to.chain_head_db.get_historical_root_hash(timestamp)
        if peer_root_hash is not None:
            return peer_root_hash
        else:
            try:
                return local_root_hash_timestamps_dict[timestamp]
            except KeyError:
                return None


    async def get_blockchain_sync_parameters(self):
        if self._sync_parameters is not None:
            if self._sync_parameters == "fully-synced":
                return None
            else:
                return self._sync_parameters
        else:
            sync_parameters = await super().get_blockchain_sync_parameters()

            if self._sync_stage_override is not None:
                if sync_parameters is not None:
                    sync_parameters.sync_stage = self._sync_stage_override

            return sync_parameters

    def get_peers_who_have_conflict_block(self, block_hash):
        if self.is_server:
            return None
        else:
            return list(self.peer_pool.peers)

    async def get_correct_block_conflict_choice_where_we_differ_from_consensus(self):
        if self.is_server:
            return None
        else:
            to_change = []
            for block_conflict_info in self.block_conflicts:
                try:
                    hash_of_correct_block = self.chain_to_sync_to.chaindb.get_canonical_block_hash(block_conflict_info.block_number, block_conflict_info.chain_address)
                    to_change.append(BlockConflictChoice(block_conflict_info.chain_address, block_conflict_info.block_number, hash_of_correct_block))
                except HeaderNotFound:
                    pass

            return to_change

    def add_block_conflict(self, chain_wallet_address, block_number) -> None:
        if not self.is_server:
            super().add_block_conflict(chain_wallet_address, block_number)