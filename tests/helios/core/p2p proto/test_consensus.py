import asyncio
import logging

import time
import random

import pytest

from typing import cast, List

from eth_keys import keys
from eth_utils import decode_hex

from helios.dev_tools import create_dev_test_blockchain_database_with_given_transactions, \
    add_transactions_to_blockchain_db, create_dev_test_random_blockchain_database, create_predefined_blockchain_database
from hp2p.constants import TIME_OFFSET_TO_FAST_SYNC_TO
from hvm.db.backends.memory import MemoryDB
from pprint import pprint
from hp2p.consensus import Consensus
from hvm import constants
from hvm import TestnetChain
from hvm.vm.forks.helios_testnet import HeliosTestnetVM

from helios.sync.full.chain import RegularChainSyncer

from tests.helios.core.integration_test_helpers import (
    FakeAsyncTestnetChain,
    FakeAsyncChainDB,
    FakeAsyncAtomicDB,
    get_random_blockchain_db, get_fresh_db,
    FakeTestnetFullNode,
    MockConsensusService,
    get_random_long_time_blockchain_db, get_predefined_blockchain_db)
from tests.helios.core.peer_helpers import (
    get_directly_linked_peers,
    MockPeerPoolWithConnectedPeers,
)


from hvm import TestnetChain
from hvm.chains.testnet import (
    TESTNET_GENESIS_PARAMS,
    TESTNET_GENESIS_STATE,
    TESTNET_GENESIS_PRIVATE_KEY,
    TESTNET_NETWORK_ID,
)

from helios.protocol.common.datastructures import SyncParameters
from hvm.constants import TIME_BETWEEN_HEAD_HASH_SAVE, GAS_TX
from hvm.vm.forks.boson.constants import MIN_TIME_BETWEEN_BLOCKS
from helios.sync.common.constants import (
    FAST_SYNC_STAGE_ID,
    CONSENSUS_MATCH_SYNC_STAGE_ID,
    ADDITIVE_SYNC_STAGE_ID,
    FULLY_SYNCED_STAGE_ID,
)
from eth_utils import to_wei, encode_hex, decode_hex
from helios.dev_tools import create_new_genesis_params_and_state
from tests.integration_test_helpers import (
    ensure_blockchain_databases_identical,
    ensure_chronological_block_hashes_are_identical
)
from queue import Queue

from hvm.constants import random_private_keys

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

private_keys = []
for i in range(len(random_private_keys)):
    private_keys.append(keys.PrivateKey(random_private_keys[i]))

@pytest.mark.asyncio
async def _test_consensus_swarm(request, event_loop, bootnode_db, client_db, peer_swarm, validation_function, waiting_function = None):

    # 0 = bootnode, 1 = client, 2 .... n = peers in swarm
    dbs_for_linking = [bootnode_db, client_db, *peer_swarm]

    # initialize array
    linked_peer_array = []
    for i in range(len(dbs_for_linking)):
        linked_peer_array.append([None]*(len(dbs_for_linking)))

    private_helios_keys = [
        TESTNET_GENESIS_PRIVATE_KEY,
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



    node_index_to_listen_with_logger = [0,1]
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

        node = FakeTestnetFullNode(dbs_for_linking[i], private_helios_keys[i])

        consensus = Consensus(context=context,
                             peer_pool=peer_pool,
                             bootstrap_nodes=bootstrap_nodes,
                             node=node
                             )

        if i not in node_index_to_listen_with_logger:
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

    if waiting_function is None:
        await wait_for_consensus_all(consensus_services)
    else:
        await waiting_function(consensus_services)

    print("WAITING FUNCTION FIRED")

    await asyncio.sleep(1)
    await validation_function(consensus_services)


@pytest.mark.asyncio
async def _build_test_consensus(request, event_loop,
                                genesis_block_timestamp = int(time.time()/1000)*1000 - 1000*1000 + 1000,
                                gap_between_genesis_block_and_first_transaction = 1000,
                                diverging_transactions_timestamp = None):
    '''
    This one creates a swarm of 4 nodes with one database, and 4 nodes with another database, then asks
    consensus which ones to choose. It checks to make sure they choose the correct one.
    The bootnode, and the first half of the peers have the same blockchain database
    The second half of the peers have a conflicting database
    Then finally, the client has only the genesis block and is asked to choose which database is in consensus.
    The first half of the peers have much more stake then the second half, so the client should choose the blockchain
    database from the first half of the nodes, which is also the one the bootnode has.
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

    if gap_between_genesis_block_and_first_transaction < MIN_TIME_BETWEEN_BLOCKS:
        gap_between_genesis_block_and_first_transaction = MIN_TIME_BETWEEN_BLOCKS

    tx_list = [
        *[[TESTNET_GENESIS_PRIVATE_KEY, private_keys[i], ((1000000 - 1000 * i) * 10 ** 18), genesis_block_timestamp + gap_between_genesis_block_and_first_transaction + MIN_TIME_BETWEEN_BLOCKS * i] for i in range(len(random_private_keys))]
    ]

    total_required_gas = sum([(to_wei(tx_key[4], 'gwei') if len(tx_key) > 4 else to_wei(1, 'gwei'))*GAS_TX for tx_key in tx_list])

    genesis_chain_stake = 100

    required_total_supply = sum([x[2] for x in tx_list if x[0] == TESTNET_GENESIS_PRIVATE_KEY]) + genesis_chain_stake + total_required_gas

    genesis_params, genesis_state = create_new_genesis_params_and_state(TESTNET_GENESIS_PRIVATE_KEY, required_total_supply,
                                                                        genesis_block_timestamp)

    # import genesis block
    TestnetChain.from_genesis(base_db, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), genesis_params,
                              genesis_state)


    # Client db has only the genesis block
    client_db = MemoryDB(base_db.kv_store.copy())

    add_transactions_to_blockchain_db(base_db, tx_list)

    # chain = TestnetChain(base_db, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    # print('AAAAAAAAAAA')
    # print('genesis')
    # print(chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address()))
    # for i in range(len(random_private_keys)):
    #     print(i)
    #     print(chain.get_vm().state.account_db.get_balance(private_keys[i].public_key.to_canonical_address()))
    # exit()
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

    bootstrap_node = TestnetChain(base_db, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    # print("XXXXXXXXXXXXXXXX")
    # print(bootstrap_node.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address()))
    # await asyncio.sleep(1000)
    bootstrap_node.min_gas_db.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=1, net_tpc_cap=100)
    consensus_root_hash_timestamps = bootstrap_node.chain_head_db.get_historical_root_hashes()

    def print_statistics(consensus, timestamp):
        print(consensus.coro_get_root_hash_consensus(timestamp, debug = True))

    async def validation(consensus_services):
        for i in range(len(consensus_services)):
            client_consensus = consensus_services[i]
            for timestamp, root_hash in consensus_root_hash_timestamps:
                client_consensus_choice = await client_consensus.coro_get_root_hash_consensus(timestamp)
                assert (client_consensus_choice == root_hash), print_statistics(client_consensus, timestamp)

            #consensus_service 0 is bootnode, it is in consensus
            #consensus_service 1 is the client. It only has genesis block and is not in consensus
            #consensus_services 2 to 2+int(num_peers_in_swarm/2) are in consensus
            #the rest of the peers are not in consensus
            await client_consensus.get_blockchain_sync_parameters()
            if i in [0, *[j+2 for j in range(int(num_peers_in_swarm / 2))]]:
                sync_parameters = await client_consensus.get_blockchain_sync_parameters()
                assert sync_parameters == None
            if i == 1:
                sync_parameters = await client_consensus.get_blockchain_sync_parameters(debug = True)
                if (genesis_block_timestamp + gap_between_genesis_block_and_first_transaction) < int(time.time()/1000)*1000-1000*1000+4*1000 or gap_between_genesis_block_and_first_transaction < TIME_BETWEEN_HEAD_HASH_SAVE:
                    assert sync_parameters.timestamp_for_root_hash == int((time.time() - TIME_OFFSET_TO_FAST_SYNC_TO) / 1000) * 1000
                else:
                    assert sync_parameters.timestamp_for_root_hash == int((genesis_block_timestamp + gap_between_genesis_block_and_first_transaction)/1000)*1000 + 1000
            if i in [j+2 for j in range(int(num_peers_in_swarm / 2),num_peers_in_swarm)]:
                timestamp = int(diverging_transactions_timestamp/1000)*1000 + 1000
                sync_parameters = await client_consensus.get_blockchain_sync_parameters(debug=True)
                if timestamp > int(time.time())-1000*1000+1000*4:
                    assert sync_parameters.timestamp_for_root_hash == timestamp
                else:
                    assert sync_parameters.timestamp_for_root_hash == int((time.time() - TIME_OFFSET_TO_FAST_SYNC_TO) / 1000) * 1000



    await _test_consensus_swarm(request, event_loop, base_db, client_db, peer_dbs, validation)


@pytest.mark.asyncio
async def test_consensus_root_hash_choice_diverging_in_fast_sync_window_1(request, event_loop):
    #FAST SYNC REGION with mismatching first root hash timestamp
    genesis_block_timestamp = int(time.time() / 1000) * 1000 - 1005*1000
    await _build_test_consensus(request, event_loop,
                                                                   gap_between_genesis_block_and_first_transaction=0,
                                                                   genesis_block_timestamp = genesis_block_timestamp)

@pytest.mark.asyncio
async def test_consensus_root_hash_choice_diverging_in_fast_sync_window_2(request, event_loop):
    # FAST SYNC REGION with matching first root hash timestamp
    genesis_block_timestamp = int(time.time() / 1000) * 1000 - 1005 * 1000
    await _build_test_consensus(request, event_loop,
                                                                   gap_between_genesis_block_and_first_transaction=1000,
                                                                   genesis_block_timestamp = genesis_block_timestamp)

@pytest.mark.asyncio
async def test_consensus_root_hash_choice_diverging_in_fast_sync_window_3(request, event_loop):
    # GENESIS IN FAST SYNC REGION BUT TX IN CONSENSUS MATCH with matching first root hash timestamp
    genesis_block_timestamp = int(time.time() / 1000) * 1000 - 1000 * 1000 - 1000*10
    await _build_test_consensus(request, event_loop,
                                                                   gap_between_genesis_block_and_first_transaction=1000*30,
                                                                   genesis_block_timestamp=genesis_block_timestamp)

@pytest.mark.asyncio
async def test_consensus_root_hash_choice_diverging_in_consensus_match_window_1(request, event_loop):
    # CONSENSUS_MATCH_REGION with mismatching first root hash timestamp
    genesis_block_timestamp = int(time.time() / 1000) * 1000 - 1000*1000 + 5000

    await _build_test_consensus(request, event_loop,
                                                                   gap_between_genesis_block_and_first_transaction=0,
                                                                   genesis_block_timestamp=genesis_block_timestamp)

@pytest.mark.asyncio
async def test_consensus_root_hash_choice_diverging_in_consensus_match_window_2(request, event_loop):
    # CONSENSUS_MATCH_REGION with matching first root hash timestamp
    genesis_block_timestamp = int(time.time() / 1000) * 1000 - 1000 * 1000 + 5000
    await _build_test_consensus(request, event_loop,
                                                                   gap_between_genesis_block_and_first_transaction=1000,
                                                                   genesis_block_timestamp=genesis_block_timestamp)


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
    genesis_block_timestamp = int(time.time() / 1000) * 1000 - 1000 * 25
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



@pytest.mark.asyncio
async def test_consensus_avg_network_min_gas(request, event_loop):

    num_peers_in_swarm = 6

    base_db = MemoryDB()
    create_predefined_blockchain_database(base_db)

    tx_list = [
        [TESTNET_GENESIS_PRIVATE_KEY, private_keys[1], 1, int(time.time())]
    ]
    add_transactions_to_blockchain_db(base_db, tx_list)

    client_db = MemoryDB(kv_store=base_db.kv_store.copy())

    peer_dbs = []
    for i in range(num_peers_in_swarm):
        peer_dbs.append(MemoryDB(kv_store=base_db.kv_store.copy()))

    # Set their minimum gas prices
    bootstrap_chain = TestnetChain(base_db, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    bootstrap_chain.min_gas_db.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=100, net_tpc_cap = 1)

    client_chain = TestnetChain(client_db, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    client_chain.min_gas_db.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=100, net_tpc_cap=1)

    for peer_db in peer_dbs:
        peer_chain = TestnetChain(peer_db, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
        peer_chain.min_gas_db.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=random.randint(1,1000), net_tpc_cap=1)

    bootstrap_historical_min_gas_price = bootstrap_chain.min_gas_db.load_historical_minimum_gas_price()
    bootstrap_historical_network_tpc_capability = bootstrap_chain.min_gas_db.load_historical_network_tpc_capability()
    
    async def validation(consensus_services: List[Consensus]):
        # avg_min_gas_limits = [await client_consensus.calculate_average_network_min_gas_limit() for client_consensus in consensus_services]
        # print(avg_min_gas_limits)
        # all_equal = all(x == avg_min_gas_limits[0] for x in avg_min_gas_limits)
        # assert(all_equal)
        
        # We also want to make sure that the nodes correctly initialized to the bootstrap node
        for consensus in consensus_services:
            chain = consensus.node.get_chain()
            node_historical_min_gas_price = chain.min_gas_db.load_historical_minimum_gas_price()
            node_historical_network_tpc_capability = chain.min_gas_db.load_historical_network_tpc_capability()
            
            assert(bootstrap_historical_min_gas_price[:-1] == node_historical_min_gas_price[:len(bootstrap_historical_min_gas_price)-1])
            assert(bootstrap_historical_network_tpc_capability[:-1] == node_historical_network_tpc_capability[:len(bootstrap_historical_network_tpc_capability)-1])


    async def wait_for_time(consensus_services):
        while True:
            # They should have the same parameters once they have received stats from all other nodes.
            length_of_stats = [len(consensus._network_min_gas_limit_statistics) for consensus in consensus_services]
            print(length_of_stats)
            if all([x >= (num_peers_in_swarm+1) for x in length_of_stats]):
                return
            await asyncio.sleep(1)
                

    await _test_consensus_swarm(request, event_loop, base_db, client_db, peer_dbs, validation, waiting_function=wait_for_time)



@pytest.fixture
def db_fresh():
    return get_fresh_db()

@pytest.fixture
def db_random():
    return get_random_blockchain_db()

@pytest.fixture
def db_random_long_time(length_in_centiseconds = 25):
    return get_random_long_time_blockchain_db(length_in_centiseconds)




class HeliosTestnetVMChain(FakeAsyncTestnetChain):
    vm_configuration = ((0, HeliosTestnetVM),)
    chaindb_class = FakeAsyncChainDB
    network_id = 1

async def wait_for_consensus(server_consensus, client_consensus):
    SYNC_TIMEOUT = 100

    async def wait_loop():

        while True:
            try:
                if await server_consensus.coro_get_root_hash_consensus(int(time.time())) == await client_consensus.coro_get_root_hash_consensus(int(time.time())):
                    return
            except Exception:
                pass

            await asyncio.sleep(1)

    await asyncio.wait_for(wait_loop(), SYNC_TIMEOUT)

async def wait_for_consensus_all(consensus_services):
    SYNC_TIMEOUT = 100

    async def wait_loop():
        while True:
            try:
                if all([await consensus_services[0].coro_get_root_hash_consensus(int(time.time())) == await rest.coro_get_root_hash_consensus(int(time.time())) and await rest.coro_get_root_hash_consensus(int(time.time())) != None for rest in consensus_services]):
                    return
            except Exception:
                pass

            await asyncio.sleep(1)

    await asyncio.wait_for(wait_loop(), SYNC_TIMEOUT)


# async def wait_for_consensus_all(consensus_services):
#     SYNC_TIMEOUT = 100
#
#     async def wait_loop():
#         while True:
#             try:
#                 if all([await consensus_services[0].coro_get_root_hash_consensus(int(time.time())) == await rest.coro_get_root_hash_consensus(int(time.time())) and await rest.coro_get_root_hash_consensus(int(time.time())) != None for rest in consensus_services]):
#                     return
#             except Exception:
#                 pass
#
#             # server_root_hash = await server_consensus.coro_get_root_hash_consensus(int(time.time()))
#             # client_root_hash = await client_consensus.coro_get_root_hash_consensus(int(time.time()))
#             #print('AAAAAAAAAAAAAA')
#             #print([await consensus_services[0].coro_get_root_hash_consensus(int(time.time())) == await rest.coro_get_root_hash_consensus(int(time.time()), debug=True) for rest in consensus_services])
#             await asyncio.sleep(1)
#
#     await asyncio.wait_for(wait_loop(), SYNC_TIMEOUT)




# if __name__ == "__main__":
#     __spec__ = 'None'
#     loop = asyncio.get_event_loop()
#     test_regular_syncer(fake_request_object(), loop)