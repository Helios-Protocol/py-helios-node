import asyncio
import logging

import time

import pytest

from typing import cast

from eth_keys import keys
from eth_utils import decode_hex

from helios.dev_tools import create_dev_test_blockchain_database_with_given_transactions, \
    add_transactions_to_blockchain_db
from hp2p.constants import TIME_OFFSET_TO_FAST_SYNC_TO
from hvm.db.backends.memory import MemoryDB

from hp2p.consensus import Consensus
from hvm import constants
from hvm import MainnetChain
from hvm.vm.forks.helios_testnet import HeliosTestnetVM

from helios.sync.full.chain import RegularChainSyncer

from tests.helios.core.integration_test_helpers import (
    FakeAsyncMainnetChain,
    FakeAsyncChainDB,
    FakeAsyncAtomicDB,
    get_random_blockchain_db, get_fresh_db,
    FakeMainnetFullNode,
    MockConsensusService,
    get_random_long_time_blockchain_db, get_predefined_blockchain_db)
from tests.helios.core.peer_helpers import (
    get_directly_linked_peers,
    MockPeerPoolWithConnectedPeers,
)
from helios.protocol.common.datastructures import SyncParameters
from hvm.constants import MIN_TIME_BETWEEN_BLOCKS, TIME_BETWEEN_HEAD_HASH_SAVE
from helios.sync.common.constants import (
    FAST_SYNC_STAGE_ID,
    CONSENSUS_MATCH_SYNC_STAGE_ID,
    ADDITIVE_SYNC_STAGE_ID,
    FULLY_SYNCED_STAGE_ID,
)

from helios.dev_tools import create_new_genesis_params_and_state
from tests.integration_test_helpers import (
    ensure_blockchain_databases_identical,
    ensure_chronological_block_hashes_are_identical
)
from queue import Queue

from hvm.constants import random_private_keys
from hvm.chains.mainnet import GENESIS_PRIVATE_KEY

from helios.utils.logging import disable_logging, enable_logging

from logging.handlers import (
    QueueListener,
    QueueHandler,
    RotatingFileHandler,
)
from hvm.tools.logging import (
    TraceLogger,
)

import os
from hp2p.consensus import Consensus
logger = logging.getLogger('helios')


@pytest.mark.asyncio
async def _test_consensus_swarm(request, event_loop, bootnode_db, client_db, peer_swarm, validation_function):

    # 0 = bootnode, 1 = client, 2 .... n = peers in swarm
    dbs_for_linking = [bootnode_db, client_db, *peer_swarm]

    # initialize array
    linked_peer_array = []
    for i in range(len(dbs_for_linking)):
        linked_peer_array.append([None]*(len(dbs_for_linking)))

    private_helios_keys = [
        GENESIS_PRIVATE_KEY,
        keys.PrivateKey(random_private_keys[0]),
        *[keys.PrivateKey(random_private_keys[i+1]) for i in range(len(peer_swarm))]
    ]

    # Create all of the linked peers
    for i in range(len(dbs_for_linking)):
        client_db = dbs_for_linking[i]
        client_private_helios_key = private_helios_keys[i]
        for j in range(len(dbs_for_linking)):
            # Don't link it with itself
            if i == j:
                continue

            if linked_peer_array[i][j] is None and linked_peer_array[j][i] is None:
                peer_db = dbs_for_linking[j]
                peer_private_helios_key = private_helios_keys[j]

                client_peer, server_peer = await get_directly_linked_peers(
                    request, event_loop,
                    alice_db=client_db,
                    bob_db=peer_db,
                    alice_private_helios_key=client_private_helios_key,
                    bob_private_helios_key=peer_private_helios_key)

                linked_peer_array[i][j] = client_peer
                linked_peer_array[j][i] = server_peer



    node_index_to_listen_with_logger = 1
    consensus_services = []
    for i in range(len(dbs_for_linking)):
        if i == 0:
            context = linked_peer_array[i][1].context
            context.chain_config.node_type = 4
            context.chain_config.network_startup_node = True
            bootstrap_nodes = []
        else:
            context = linked_peer_array[i][0].context
            bootstrap_nodes = [linked_peer_array[i][0].remote]

        peer_pool = MockPeerPoolWithConnectedPeers([x for x in linked_peer_array[i] if x is not None])

        node = FakeMainnetFullNode(dbs_for_linking[i], private_helios_keys[i])

        consensus = Consensus(context=context,
                             peer_pool=peer_pool,
                             bootstrap_nodes=bootstrap_nodes,
                             node=node
                             )

        if i != node_index_to_listen_with_logger:
            # disable logger by renaming it to one we arent listening to
            consensus.logger = logging.getLogger('dummy')
            pass

        consensus_services.append(consensus)


    asyncio.ensure_future(consensus_services[0].run())


    def finalizer():
        event_loop.run_until_complete(asyncio.gather(
            *[x.cancel() for x in consensus_services],
            loop=event_loop,
        ))
        # Yield control so that client/server.run() returns, otherwise asyncio will complain.
        event_loop.run_until_complete(asyncio.sleep(0.1))

    request.addfinalizer(finalizer)

    for i in range(2, len(consensus_services)):
        asyncio.ensure_future(consensus_services[i].run())

    asyncio.ensure_future(consensus_services[1].run())

    await wait_for_consensus_all(consensus_services)

    print("WAITING FUNCTION FIRED")

    #await asyncio.sleep(1000)
    await validation_function(consensus_services)


@pytest.mark.asyncio
async def _build_test_consensus(request, event_loop,
                                genesis_block_timestamp = int(time.time()/1000)*1000 - 1000*1000 + 1000,
                                gap_between_genesis_block_and_first_transaction = 1000,
                                diverging_transactions_timestamp = None):
    '''
    This one creates a swarm of 4 nodes with one database, and 4 nodes with another database, then asks
    consensus which ones to choose. It checks to make sure they choose the correct one.
    :param request:
    :param event_loop:
    :return:
    '''


    num_peers_in_swarm = 8

    # If this is less than TIME_BETWEEN_HEAD_HASH_SAVE, it will result in FAST SYNC MODE because even the first
    # chronological block hash will be different.
    #gap_between_genesis_block_and_first_transaction = 1000

    base_db = MemoryDB()

    #genesis_block_timestamp = int(time.time()/1000)*1000 - 1000*1000 + 1000
    #genesis_block_timestamp = 1547288000

    private_keys = []
    for i in range(len(random_private_keys)):
        private_keys.append(keys.PrivateKey(random_private_keys[i]))


    tx_list = [
        *[[GENESIS_PRIVATE_KEY, private_keys[i], 1000000-1000*i, genesis_block_timestamp + gap_between_genesis_block_and_first_transaction + MIN_TIME_BETWEEN_BLOCKS * i] for i in range(len(random_private_keys))]
    ]


    genesis_chain_stake = 100

    required_total_supply = sum([x[2]+21000 for x in tx_list if x[0] == GENESIS_PRIVATE_KEY]) + genesis_chain_stake

    genesis_params, genesis_state = create_new_genesis_params_and_state(GENESIS_PRIVATE_KEY, required_total_supply,
                                                                        genesis_block_timestamp)

    # import genesis block
    MainnetChain.from_genesis(base_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), genesis_params,
                              genesis_state)


    # Client db has only the genesis block
    client_db = MemoryDB(base_db.kv_store.copy())

    add_transactions_to_blockchain_db(base_db, tx_list)

    # stake for the first half of chains should be from node 1 to node n:
    # 100
    # 1000000
    # 999000
    # 998000
    # 997000
    # 996000
    # 995000
    # 994000
    # 993000
    # 992000


    peer_dbs = []
    for i in range(int(num_peers_in_swarm/2)):
        peer_dbs.append(MemoryDB(base_db.kv_store.copy()))

    #last_block_timestamp = tx_list[-1][-1]
    # additional_tx_list_for_competing_db = [
    #     [private_keys[4], private_keys[1], 100, last_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS * 1],
    #     [private_keys[4], private_keys[2], 100, last_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS * 2],
    #     [private_keys[4], private_keys[3], 100, last_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS * 3],
    # ]

    if diverging_transactions_timestamp is None:
        diverging_transactions_timestamp = tx_list[-1][-1] + TIME_BETWEEN_HEAD_HASH_SAVE

    additional_tx_list_for_competing_db = [
        [private_keys[4], private_keys[1], 100, diverging_transactions_timestamp + MIN_TIME_BETWEEN_BLOCKS * 0],
        [private_keys[4], private_keys[2], 100, diverging_transactions_timestamp + MIN_TIME_BETWEEN_BLOCKS * 1],
        [private_keys[4], private_keys[3], 100, diverging_transactions_timestamp + MIN_TIME_BETWEEN_BLOCKS * 2],
    ]
    competing_base_db = MemoryDB(base_db.kv_store.copy())
    add_transactions_to_blockchain_db(competing_base_db, additional_tx_list_for_competing_db)

    # stake for the second half of chains should be from node 1 to node n:
    # 100
    # 1000000
    # 999100
    # 998100
    # 997100
    # 932700
    # 995000
    # 994000
    # 993000
    # 992000

    # for peer node 7 for root hash 1
    # 100 + 997100 + 996100 + 995100 + 930700

    for i in range(int(num_peers_in_swarm / 2),num_peers_in_swarm):
        peer_dbs.append(MemoryDB(competing_base_db.kv_store.copy()))

    bootstrap_node = MainnetChain(base_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    bootstrap_node.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=1, net_tpc_cap=100, tpc=1)
    consensus_root_hash_timestamps = bootstrap_node.chain_head_db.get_historical_root_hashes()


    async def validation(consensus_services):
        for i in range(len(consensus_services)):
            client_consensus = consensus_services[i]
            for timestamp, root_hash in consensus_root_hash_timestamps:
                client_consensus_choice = await client_consensus.coro_get_root_hash_consensus(timestamp)
                assert (client_consensus_choice == root_hash)

            if i in [0, 2, 3, 4, 5]:
                assert await client_consensus.get_blockchain_sync_parameters() == None
            if i == 1:
                sync_parameters = await client_consensus.get_blockchain_sync_parameters(debug = True)
                if (genesis_block_timestamp + gap_between_genesis_block_and_first_transaction) < int(time.time()/1000)*1000-1000*1000 or gap_between_genesis_block_and_first_transaction < TIME_BETWEEN_HEAD_HASH_SAVE:
                    assert sync_parameters.timestamp_for_root_hash == int((time.time() - TIME_OFFSET_TO_FAST_SYNC_TO) / 1000) * 1000
                else:
                    assert sync_parameters.timestamp_for_root_hash == int((genesis_block_timestamp + gap_between_genesis_block_and_first_transaction)/1000)*1000 + 1000
            if i in [6,7,8,9]:
                timestamp = int(diverging_transactions_timestamp/1000)*1000 + 1000
                sync_parameters = await client_consensus.get_blockchain_sync_parameters(debug=True)
                assert sync_parameters.timestamp_for_root_hash == timestamp



    await _test_consensus_swarm(request, event_loop, base_db, client_db, peer_dbs, validation)

#
# @pytest.mark.asyncio
# async def test_consensus_root_hash_choice_diverging_in_fast_sync_window_1(request, event_loop):
#     #FAST SYNC REGION with mismatching first root hash timestamp
#     genesis_block_timestamp = int(time.time() / 1000) * 1000 - 1000*1000
#     await _build_test_consensus(request, event_loop,
#                                                                    gap_between_genesis_block_and_first_transaction=0,
#                                                                    genesis_block_timestamp = genesis_block_timestamp)
#
# @pytest.mark.asyncio
# async def test_consensus_root_hash_choice_diverging_in_fast_sync_window_2(request, event_loop):
#     # FAST SYNC REGION with matching first root hash timestamp
#     genesis_block_timestamp = int(time.time() / 1000) * 1000 - 1000 * 1000
#     await _build_test_consensus(request, event_loop,
#                                                                    gap_between_genesis_block_and_first_transaction=1000,
#                                                                    genesis_block_timestamp = genesis_block_timestamp)
#
# @pytest.mark.asyncio
# async def test_consensus_root_hash_choice_diverging_in_fast_sync_window_3(request, event_loop):
#     # GENESIS IN FAST SYNC REGION BUT TX IN CONSENSUS MATCH with matching first root hash timestamp
#     genesis_block_timestamp = int(time.time() / 1000) * 1000 - 1000 * 1000 - 1000*10
#     await _build_test_consensus(request, event_loop,
#                                                                    gap_between_genesis_block_and_first_transaction=1000*30,
#                                                                    genesis_block_timestamp=genesis_block_timestamp)
#
# @pytest.mark.asyncio
# async def test_consensus_root_hash_choice_diverging_in_consensus_match_window_1(request, event_loop):
#     # CONSENSUS_MATCH_REGION with mismatching first root hash timestamp
#     genesis_block_timestamp = int(time.time() / 1000) * 1000 - 1000*1000 + 1000
#
#     await _build_test_consensus(request, event_loop,
#                                                                    gap_between_genesis_block_and_first_transaction=0,
#                                                                    genesis_block_timestamp=genesis_block_timestamp)
#
# @pytest.mark.asyncio
# async def test_consensus_root_hash_choice_diverging_in_consensus_match_window_2(request, event_loop):
#     # CONSENSUS_MATCH_REGION with matching first root hash timestamp
#     genesis_block_timestamp = int(time.time() / 1000) * 1000 - 1000 * 1000 + 1000
#     await _build_test_consensus(request, event_loop,
#                                                                    gap_between_genesis_block_and_first_transaction=1000,
#                                                                    genesis_block_timestamp=genesis_block_timestamp)



@pytest.mark.asyncio
async def test_consensus_root_hash_choice_diverging_in_additive_sync_window_1(request, event_loop):
    # GENESIS IN FAST SYNC REGION BUT TX IN ADDITIVE with matching first root hash timestamp
    genesis_block_timestamp = int(time.time() / 1000) * 1000 - 1000 * 1000
    diverging_transactions_timestamp = int(time.time() / 1000) * 1000 - 1000
    await _build_test_consensus(request, event_loop,
                                gap_between_genesis_block_and_first_transaction=1000,
                                genesis_block_timestamp=genesis_block_timestamp,
                                diverging_transactions_timestamp=diverging_transactions_timestamp)

@pytest.mark.asyncio
async def test_consensus_root_hash_choice_diverging_in_additive_sync_window_2(request, event_loop):
    # GENESIS IN FAST SYNC REGION BUT TX IN ADDITIVE with matching first root hash timestamp
    genesis_block_timestamp = int(time.time() / 1000) * 1000 - 1000 * 1000 + 1000
    diverging_transactions_timestamp = int(time.time() / 1000) * 1000 - 1000
    await _build_test_consensus(request, event_loop,
                                gap_between_genesis_block_and_first_transaction=1000,
                                genesis_block_timestamp=genesis_block_timestamp,
                                diverging_transactions_timestamp=diverging_transactions_timestamp)

@pytest.mark.asyncio
async def test_consensus_root_hash_choice_diverging_in_additive_sync_window_3(request, event_loop):
    # GENESIS IN FAST SYNC REGION BUT TX IN ADDITIVE with matching first root hash timestamp
    genesis_block_timestamp = int(time.time() / 1000) * 1000 - 1000 * 10
    diverging_transactions_timestamp = int(time.time() / 1000) * 1000 - 1000
    await _build_test_consensus(request, event_loop,
                                gap_between_genesis_block_and_first_transaction=1000,
                                genesis_block_timestamp=genesis_block_timestamp,
                                diverging_transactions_timestamp=diverging_transactions_timestamp)


@pytest.mark.asyncio
async def test_consensus_root_hash_choice_diverging_in_additive_sync_window_4(request, event_loop):
    # GENESIS IN FAST SYNC REGION BUT TX IN ADDITIVE with matching first root hash timestamp
    genesis_block_timestamp = int(time.time() / 1000) * 1000 - 1000 * 1000 - 1000*10
    diverging_transactions_timestamp = int(time.time() / 1000) * 1000 - 1000
    await _build_test_consensus(request, event_loop,
                                gap_between_genesis_block_and_first_transaction=1000,
                                genesis_block_timestamp=genesis_block_timestamp,
                                diverging_transactions_timestamp=diverging_transactions_timestamp)



@pytest.fixture
def db_fresh():
    return get_fresh_db()

@pytest.fixture
def db_random():
    return get_random_blockchain_db()

@pytest.fixture
def db_random_long_time(length_in_centiseconds = 25):
    return get_random_long_time_blockchain_db(length_in_centiseconds)


SENDER = keys.PrivateKey(
    decode_hex("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee"))
RECEIVER = keys.PrivateKey(
    decode_hex("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"))
GENESIS_PARAMS = {
    'parent_hash': constants.GENESIS_PARENT_HASH,
    'uncles_hash': constants.EMPTY_UNCLE_HASH,
    'coinbase': constants.ZERO_ADDRESS,
    'transaction_root': constants.BLANK_ROOT_HASH,
    'receipt_root': constants.BLANK_ROOT_HASH,
    'bloom': 0,
    'difficulty': 5,
    'block_number': constants.GENESIS_BLOCK_NUMBER,
    'gas_limit': constants.GENESIS_GAS_LIMIT,
    'gas_used': 0,
    'timestamp': 1514764800,
    'extra_data': constants.GENESIS_EXTRA_DATA,
    'nonce': constants.GENESIS_NONCE
}
GENESIS_STATE = {
    SENDER.public_key.to_canonical_address(): {
        "balance": 100000000000000000,
        "code": b"",
        "nonce": 0,
        "storage": {}
    }
}


class HeliosTestnetVMChain(FakeAsyncMainnetChain):
    vm_configuration = ((0, HeliosTestnetVM),)
    chaindb_class = FakeAsyncChainDB
    network_id = 1

async def wait_for_consensus(server_consensus, client_consensus):
    SYNC_TIMEOUT = 1000

    async def wait_loop():

        while await server_consensus.coro_get_root_hash_consensus(int(time.time())) != await client_consensus.coro_get_root_hash_consensus(int(time.time())):
            server_root_hash = await server_consensus.coro_get_root_hash_consensus(int(time.time()))
            client_root_hash = await client_consensus.coro_get_root_hash_consensus(int(time.time()))
            # print('AAAAAAAAAAAAAA')
            # print(int(time.time()/1000)*1000)
            # print(server_root_hash)
            # print(client_root_hash)
            await asyncio.sleep(1)

    await asyncio.wait_for(wait_loop(), SYNC_TIMEOUT)

async def wait_for_consensus_all(consensus_services):
    SYNC_TIMEOUT = 1000

    async def wait_loop():
        while not all([await consensus_services[0].coro_get_root_hash_consensus(int(time.time())) == await rest.coro_get_root_hash_consensus(int(time.time())) for rest in consensus_services]):
            # server_root_hash = await server_consensus.coro_get_root_hash_consensus(int(time.time()))
            # client_root_hash = await client_consensus.coro_get_root_hash_consensus(int(time.time()))
            print('AAAAAAAAAAAAAA')
            print([await consensus_services[0].coro_get_root_hash_consensus(int(time.time())) == await rest.coro_get_root_hash_consensus(int(time.time()), debug=True) for rest in consensus_services])
            await asyncio.sleep(1)

    await asyncio.wait_for(wait_loop(), SYNC_TIMEOUT)



# if __name__ == "__main__":
#     __spec__ = 'None'
#     loop = asyncio.get_event_loop()
#     test_regular_syncer(fake_request_object(), loop)