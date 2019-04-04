import asyncio
import logging

import time

import pytest

from eth_keys import keys
from eth_utils import decode_hex

from helios.dev_tools import add_transactions_to_blockchain_db, add_random_transactions_to_db_for_time_window
from hp2p.consensus import Consensus
from hp2p.constants import ADDITIVE_SYNC_MODE_CUTOFF
from hvm import constants
from hvm import MainnetChain
from hvm.constants import TIME_BETWEEN_HEAD_HASH_SAVE
from hvm.vm.forks.helios_testnet import HeliosTestnetVM

from helios.sync.full.chain import RegularChainSyncer, NewBlockQueueItem

from tests.helios.core.integration_test_helpers import (
    FakeAsyncMainnetChain,
    FakeAsyncChainDB,
    FakeAsyncAtomicDB,
    get_random_blockchain_db, get_fresh_db,
    FakeMainnetFullNode,
    MockConsensusService,
    get_random_long_time_blockchain_db, get_random_blockchain_to_time)
from tests.helios.core.peer_helpers import (
    get_directly_linked_peers,
    MockPeerPoolWithConnectedPeers,
)
from helios.protocol.common.datastructures import SyncParameters

from helios.sync.common.constants import (
    FAST_SYNC_STAGE_ID,
    CONSENSUS_MATCH_SYNC_STAGE_ID,
    ADDITIVE_SYNC_STAGE_ID,
    FULLY_SYNCED_STAGE_ID,
)
from hvm.db.backends.memory import MemoryDB

from tests.integration_test_helpers import (
    ensure_blockchain_databases_identical,
    ensure_chronological_block_hashes_are_identical
)
from hvm.chains.mainnet import (
    GENESIS_PRIVATE_KEY,
)

logger = logging.getLogger('helios')


@pytest.mark.asyncio
async def _test_sync_with_fixed_sync_parameters(request,
                                                event_loop,
                                                client_db,
                                                server_db,
                                                timestamp_to_sync_to,
                                                sync_stage_id,
                                                validation_function,
                                                blocks_to_import = None,
                                                blocks_to_import_from_rpc = False):
    client_peer, server_peer = await get_directly_linked_peers(
        request, event_loop,
        alice_db=client_db,
        bob_db=server_db)

    client_node = FakeMainnetFullNode(
        base_db = client_peer.context.base_db,
        priv_key = client_peer.context.chains[0].private_key,
    )

    client_peer_pool = MockPeerPoolWithConnectedPeers([client_peer])

    # lets do a fast sync to newest root hash timestamp
    expected_root_hash = server_peer.chain_head_db.get_historical_root_hash(timestamp_to_sync_to)
    existing_root_hash = client_peer.chain_head_db.get_historical_root_hash(timestamp_to_sync_to)


    client_sync_parameters = SyncParameters(timestamp_to_sync_to,
                                            existing_root_hash,
                                            expected_root_hash,
                                            [client_peer],
                                            sync_stage_id)

    client_consensus = MockConsensusService(sync_parameters=client_sync_parameters)

    client = RegularChainSyncer(
        context = client_peer.context,
        peer_pool = client_peer_pool,
        consensus = client_consensus,
        node = client_node,
    )

    server_node = FakeMainnetFullNode(
        base_db=server_peer.context.base_db,
        priv_key=server_peer.context.chains[0].private_key,
    )

    server_peer_pool = MockPeerPoolWithConnectedPeers([server_peer])

    server_consensus = MockConsensusService(sync_parameters ="fully-synced")

    server_context = server_peer.context
    server_context.chain_config.node_type = 4
    server_context.chain_config.network_startup_node = True
    server = RegularChainSyncer(
        context=server_peer.context,
        peer_pool=server_peer_pool,
        consensus=server_consensus,
        node=server_node,
    )

    asyncio.ensure_future(server.run())

    def finalizer():
        event_loop.run_until_complete(asyncio.gather(
            client.cancel(),
            server.cancel(),
            loop=event_loop,
        ))
        # Yield control so that client/server.run() returns, otherwise asyncio will complain.
        event_loop.run_until_complete(asyncio.sleep(0.1))
    request.addfinalizer(finalizer)

    asyncio.ensure_future(client.run())

    if blocks_to_import is not None:
        for block in blocks_to_import:
            new_block_queue_item = NewBlockQueueItem(block, from_rpc=blocks_to_import_from_rpc)
            client._new_blocks_to_import.put_nowait(new_block_queue_item)

    #await client.run()
    await wait_for_chain_head_hash(client.chain_head_db, expected_root_hash, timestamp_to_sync_to)

    await asyncio.sleep(0.2)

    validation_function(server_db, client_db)



@pytest.mark.asyncio
async def _test_sync_with_variable_sync_parameters(request,
                                                   event_loop,
                                                   client_db,
                                                   server_db,
                                                   validation_function,
                                                   sync_stage_id_override = None,
                                                   waiting_function=None,
                                                   blocks_to_import=None,
                                                   blocks_to_import_from_rpc=False
                                                   ):
    client_peer, server_peer = await get_directly_linked_peers(
        request, event_loop,
        alice_db=client_db,
        bob_db=server_db)


    client_node = FakeMainnetFullNode(
        base_db = client_peer.context.base_db,
        priv_key = client_peer.context.chains[0].private_key,
    )

    client_peer_pool = MockPeerPoolWithConnectedPeers([client_peer])

    expected_root_hash_timestamp = server_peer.chain_head_db.get_historical_root_hashes()[-1]

    client_consensus = MockConsensusService(client_peer.chain_head_db,
                                            client_peer_pool,
                                            chain_to_sync_to=server_peer.context.chains[0],
                                            sync_stage_override = sync_stage_id_override)


    client = RegularChainSyncer(
        context = client_peer.context,
        peer_pool = client_peer_pool,
        consensus = client_consensus,
        node = client_node,
    )

    server_node = FakeMainnetFullNode(
        base_db=server_peer.context.base_db,
        priv_key=server_peer.context.chains[0].private_key,
    )

    server_peer_pool = MockPeerPoolWithConnectedPeers([server_peer])

    server_consensus = MockConsensusService(sync_parameters="fully-synced",
                                            peer_pool = server_peer_pool,
                                            is_server = True)

    server_context = server_peer.context
    server_context.chain_config.node_type = 4
    server_context.chain_config.network_startup_node = True
    server = RegularChainSyncer(
        context=server_peer.context,
        peer_pool=server_peer_pool,
        consensus=server_consensus,
        node=server_node,
    )

    server.logger = logging.getLogger('dummy')

    asyncio.ensure_future(server.run())

    def finalizer():
        event_loop.run_until_complete(asyncio.gather(
            client.cancel(),
            server.cancel(),
            loop=event_loop,
        ))
        # Yield control so that client/server.run() returns, otherwise asyncio will complain.
        event_loop.run_until_complete(asyncio.sleep(0.1))
    request.addfinalizer(finalizer)

    asyncio.ensure_future(client.run())

    if blocks_to_import is not None:
        for block in blocks_to_import:
            new_block_queue_item = NewBlockQueueItem(block, from_rpc=blocks_to_import_from_rpc)
            client._new_blocks_to_import.put_nowait(new_block_queue_item)

    if waiting_function is None:
        await wait_for_both_nodes_to_be_synced(client.chain_head_db, server.chain_head_db)
    else:
        await waiting_function(client, server)

    #give the nodes a second to finish. They might still be writing to the database.
    await asyncio.sleep(0.2)

    validation_function(server_db, client_db)
    #ensure_blockchain_databases_identical(server_db, client_db)

#
# Testing syncing of blockchain databases between nodes
#
@pytest.mark.asyncio
async def test_fast_sync_1(request, event_loop):

    genesis_time = int(time.time() / 1000) * 1000 - 1000 * 1100
    equal_to_time = int(time.time() / 1000) * 1000 - 1000 * 1095

    server_db = get_random_blockchain_to_time(genesis_time, equal_to_time)
    client_db = MemoryDB(kv_store=server_db.kv_store.copy())

    add_random_transactions_to_db_for_time_window(server_db, equal_to_time, equal_to_time + 1000 * 5)

    node_2 = MainnetChain(client_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    node_2.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=1, net_tpc_cap=100, tpc=1)

    await _test_sync_with_variable_sync_parameters(request, event_loop, client_db, server_db, ensure_blockchain_databases_identical, FAST_SYNC_STAGE_ID)

@pytest.mark.asyncio
async def test_fast_sync_2(request, event_loop):
    genesis_time = int(time.time() / 1000) * 1000 - 1000 * 1100
    equal_to_time = int(time.time() / 1000) * 1000 - 1000 * 1095

    server_db = get_random_blockchain_to_time(genesis_time, equal_to_time)
    client_db = MemoryDB(kv_store=server_db.kv_store.copy())

    add_random_transactions_to_db_for_time_window(client_db, equal_to_time, equal_to_time + 1000 * 5)

    node_2 = MainnetChain(client_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    node_2.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=1, net_tpc_cap=100, tpc=1)

    await _test_sync_with_variable_sync_parameters(request, event_loop, client_db, server_db,
                                                   ensure_blockchain_databases_identical, FAST_SYNC_STAGE_ID)

# @pytest.mark.asyncio
# async def test_fast_sync_3(request, event_loop):
#     client_db, server_db = get_random_long_time_blockchain_db(25), get_random_long_time_blockchain_db(25)
#     node_1 = MainnetChain(server_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
#     newest_timestamp = node_1.chain_head_db.get_historical_root_hashes()[-1][0]
#     await _test_sync_with_fixed_sync_parameters(request, event_loop, client_db, server_db, newest_timestamp, FAST_SYNC_STAGE_ID, ensure_blockchain_databases_identical)


@pytest.mark.asyncio
async def test_fast_sync_4(request, event_loop):
    '''
    Blockchain databases of client and server match up to a point before chronological block windows starts, but there are additional
    blocks in the server's db after that time.
    :param request:
    :param event_loop:
    :return:
    '''

    genesis_time = int(time.time()/1000)*1000-1000*1100
    equal_to_time = int(time.time()/1000)*1000-1000*1095
    new_blocks_start_time = int(time.time()/1000)*1000-1000*25
    new_blocks_end_time = int(time.time() / 1000) * 1000 - 1000*3

    server_db = get_random_blockchain_to_time(genesis_time, equal_to_time)
    client_db = MemoryDB(kv_store = server_db.kv_store.copy())

    add_random_transactions_to_db_for_time_window(server_db, equal_to_time, equal_to_time+1000*5)

    add_random_transactions_to_db_for_time_window(server_db, new_blocks_start_time, new_blocks_end_time)

    client_node = MainnetChain(client_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    client_node.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=1, net_tpc_cap=100, tpc=1)

    await _test_sync_with_variable_sync_parameters(request, event_loop, client_db, server_db, ensure_blockchain_databases_identical)

@pytest.mark.asyncio
async def test_fast_sync_5(request, event_loop):
    '''
    Blockchain databases of client and server match up to a point before chronological block windows starts, but there are additional
    blocks in the server's db after that time.
    :param request:
    :param event_loop:
    :return:
    '''
    for i in range(5):
        genesis_time = int(time.time()/1000)*1000-1000*1100
        equal_to_time = int(time.time()/1000)*1000-1000*1095
        new_blocks_start_time = int(time.time()/1000)*1000-1000*25
        new_blocks_end_time = int(time.time() / 1000) * 1000 - 1000*3

        server_db = get_random_blockchain_to_time(genesis_time, equal_to_time)
        client_db = MemoryDB(kv_store = server_db.kv_store.copy())

        add_random_transactions_to_db_for_time_window(client_db, equal_to_time, equal_to_time+1000*5)

        add_random_transactions_to_db_for_time_window(client_db, new_blocks_start_time, new_blocks_end_time)

        client_node = MainnetChain(client_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
        client_node.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=1, net_tpc_cap=100, tpc=1)

        await _test_sync_with_variable_sync_parameters(request, event_loop, client_db, server_db, ensure_blockchain_databases_identical)



@pytest.mark.asyncio
async def test_consensus_match_sync_1(request, event_loop):
    #client_db, server_db = db_fresh, db_random_long_time
    client_db, server_db = get_fresh_db(), get_random_long_time_blockchain_db(25)
    node_2 = MainnetChain(client_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    node_2.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price = 1, net_tpc_cap=100, tpc=1)

    await _test_sync_with_variable_sync_parameters(request, event_loop, client_db, server_db, ensure_blockchain_databases_identical,  CONSENSUS_MATCH_SYNC_STAGE_ID)


@pytest.mark.asyncio
async def test_consensus_match_sync_2(request, event_loop):
    server_db, client_db = get_fresh_db(), get_random_long_time_blockchain_db(25)
    node_2 = MainnetChain(client_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    node_2.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price = 1, net_tpc_cap=100, tpc=1)
    await _test_sync_with_variable_sync_parameters(request, event_loop, client_db, server_db, ensure_blockchain_databases_identical,  CONSENSUS_MATCH_SYNC_STAGE_ID)




@pytest.mark.asyncio
async def test_consensus_match_sync_3(request, event_loop):
    client_db, server_db = get_random_long_time_blockchain_db(25), get_random_long_time_blockchain_db(25)
    node_2 = MainnetChain(client_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    node_2.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price = 1, net_tpc_cap=100, tpc=1)
    await _test_sync_with_variable_sync_parameters(request, event_loop, client_db, server_db, ensure_blockchain_databases_identical,  CONSENSUS_MATCH_SYNC_STAGE_ID)

@pytest.mark.asyncio
async def test_consensus_match_sync_4(request, event_loop):
    '''
    Blockchain databases of client and server match up to a point within the consensus match stage, but there are additional
    blocks in the server's db after that time.
    :param request:
    :param event_loop:
    :return:
    '''

    genesis_time = int(time.time()/1000)*1000-1000*900
    equal_to_time = int(time.time()/1000)*1000-1000*890
    new_blocks_start_time = int(time.time()/1000)*1000-1000*25
    new_blocks_end_time = int(time.time() / 1000) * 1000 - 1000*3

    server_db = get_random_blockchain_to_time(genesis_time, equal_to_time)
    client_db = MemoryDB(kv_store = server_db.kv_store.copy())

    add_random_transactions_to_db_for_time_window(server_db, equal_to_time, equal_to_time+1000*5)

    add_random_transactions_to_db_for_time_window(server_db, new_blocks_start_time, new_blocks_end_time)

    client_node = MainnetChain(client_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    client_node.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=1, net_tpc_cap=100, tpc=1)

    await _test_sync_with_variable_sync_parameters(request, event_loop, client_db, server_db, ensure_blockchain_databases_identical)





@pytest.mark.asyncio
async def test_additive_sync_1(request, event_loop):
    client_db, server_db = get_fresh_db(), get_random_long_time_blockchain_db(10)
    node_2 = MainnetChain(client_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    node_2.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price = 1, net_tpc_cap=100, tpc=1)
    await _test_sync_with_variable_sync_parameters(request, event_loop, client_db, server_db, ensure_blockchain_databases_identical,  ADDITIVE_SYNC_STAGE_ID)

@pytest.mark.asyncio
async def test_additive_sync_2(request, event_loop):
    client_db, server_db = get_random_long_time_blockchain_db(10), get_fresh_db()
    node_1 = MainnetChain(server_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    node_1.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price = 1, net_tpc_cap=100, tpc=1)
    await _test_sync_with_variable_sync_parameters(request, event_loop, client_db, server_db, ensure_blockchain_databases_identical, ADDITIVE_SYNC_STAGE_ID)

# This test has both nodes with conflicting blocks. On additive sync mode, so both nodes will keep sending each other
# their missing blocks, which the node wont import yet because it waits for the consensus object to decide which block is in
# consensus. The sync loop will loop indefinitely until the conflicts are resolved by consensus.
# So this bubbles down to the conflict block system to resolve the conflicts and bring the nodes into sync.
# This currently tests the block conflict system adequately as well. Will make more block conflict system tests
# later after optimizing the code.
@pytest.mark.asyncio
async def test_additive_sync_3(request, event_loop):
    client_db, server_db = get_random_long_time_blockchain_db(10), get_random_long_time_blockchain_db(10)
    node_1 = MainnetChain(server_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    node_1.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price = 1, net_tpc_cap=100, tpc=1)
    node_2 = MainnetChain(client_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    node_2.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=1, net_tpc_cap=100, tpc=1)
    await _test_sync_with_variable_sync_parameters(request, event_loop, client_db, server_db, ensure_blockchain_databases_identical, ADDITIVE_SYNC_STAGE_ID)


@pytest.mark.asyncio
async def test_additive_sync_4(request, event_loop):
    '''
    Blockchain databases of client and server match up to a point within the consensus match stage, but there are additional
    blocks in the server's db after that time.
    :param request:
    :param event_loop:
    :return:
    '''

    genesis_time = int(time.time()/1000)*1000-1000*25
    equal_to_time = int(time.time()/1000)*1000-1000*2

    server_db = get_random_blockchain_to_time(genesis_time, equal_to_time)
    client_db = MemoryDB(kv_store = server_db.kv_store.copy())

    tx_list = [[GENESIS_PRIVATE_KEY, RECEIVER, 100, int(time.time()-2000)],
               [GENESIS_PRIVATE_KEY, RECEIVER, 100, int(time.time() - 1500)],
               [GENESIS_PRIVATE_KEY, RECEIVER, 100, int(time.time() - 1000)]]

    add_transactions_to_blockchain_db(server_db, tx_list)

    client_node = MainnetChain(client_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    client_node.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=1, net_tpc_cap=100, tpc=1)
    server_node = MainnetChain(server_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    server_node.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=1, net_tpc_cap=100, tpc=1)

    await _test_sync_with_variable_sync_parameters(request, event_loop, client_db, server_db, ensure_blockchain_databases_identical)


@pytest.mark.asyncio
async def test_sparse_sync_1(request, event_loop):
    '''
    Blockchain databases of client and server match up to a point within the consensus match stage, but there are additional
    blocks in the server's db after that time.
    :param request:
    :param event_loop:
    :return:
    '''

    genesis_time = int(time.time()/1000)*1000-1000*900
    equal_to_time = int(time.time()/1000)*1000-1000*890

    server_db = get_random_blockchain_to_time(genesis_time, equal_to_time)
    client_db = MemoryDB(kv_store = server_db.kv_store.copy())

    add_random_transactions_to_db_for_time_window(server_db, equal_to_time, equal_to_time+1000*5)

    tx_list = [[GENESIS_PRIVATE_KEY, RECEIVER, 100, int(time.time()/1000)*1000-1000*800],
               [GENESIS_PRIVATE_KEY, RECEIVER, 100, int(time.time()/1000)*1000-1000*700],
               [GENESIS_PRIVATE_KEY, RECEIVER, 100, int(time.time()/1000)*1000-1000*100],
               [GENESIS_PRIVATE_KEY, RECEIVER, 100, int(time.time()/1000)*1000-1000*5],
               [GENESIS_PRIVATE_KEY, RECEIVER, 100, int(time.time()/1000)*1000-1000*1]]

    add_transactions_to_blockchain_db(server_db, tx_list)

    client_node = MainnetChain(client_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    client_node.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=1, net_tpc_cap=100, tpc=1)

    await _test_sync_with_variable_sync_parameters(request, event_loop, client_db, server_db, ensure_blockchain_databases_identical)


@pytest.mark.asyncio
async def test_sparse_sync_2(request, event_loop):
    '''
    Blockchain databases of client and server match up to a point within the consensus match stage, but there are additional
    blocks in the server's db after that time.
    :param request:
    :param event_loop:
    :return:
    '''

    genesis_time = int(time.time()/1000)*1000-1000*900
    equal_to_time = int(time.time()/1000)*1000-1000*890

    server_db = get_random_blockchain_to_time(genesis_time, equal_to_time)
    client_db = MemoryDB(kv_store = server_db.kv_store.copy())

    add_random_transactions_to_db_for_time_window(server_db, equal_to_time, equal_to_time+1000*5)

    tx_list = [[GENESIS_PRIVATE_KEY, RECEIVER, 100, int(time.time()/1000)*1000-1000*800],
               [GENESIS_PRIVATE_KEY, RECEIVER, 100, int(time.time()/1000)*1000-1000*700],
               [GENESIS_PRIVATE_KEY, RECEIVER, 100, int(time.time()/1000)*1000-1000*100],
               [GENESIS_PRIVATE_KEY, RECEIVER, 100, int(time.time()/1000)*1000-1000*5],
               [GENESIS_PRIVATE_KEY, RECEIVER, 100, int(time.time()/1000)*1000-1000*1]]

    add_transactions_to_blockchain_db(client_db, tx_list)

    client_node = MainnetChain(client_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    client_node.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=1, net_tpc_cap=100, tpc=1)

    await _test_sync_with_variable_sync_parameters(request, event_loop, client_db, server_db, ensure_blockchain_databases_identical)

#
# Testing importing blocks
#
#

@pytest.mark.asyncio
async def _setup_test_import_blocks(request,
                                    event_loop,
                                    new_blocks_db,
                                    new_blocks,
                                    simulate_importing_from_rpc,
                                    expect_blocks_to_import,
                                    node_min_gas_price = 1):
    client_db, server_db, fresh_db = get_fresh_db(), get_fresh_db(), get_fresh_db()
    node_1 = MainnetChain(server_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    node_1.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=node_min_gas_price, net_tpc_cap=100, tpc=1)
    node_2 = MainnetChain(client_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    node_2.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=node_min_gas_price, net_tpc_cap=100, tpc=1)

    if expect_blocks_to_import:
        expected_db = new_blocks_db
    else:
        expected_db = fresh_db

    async def waiting_function(client, server):
        SYNC_TIMEOUT = 100

        async def wait_loop():
            while (
                    (client.chain_head_db.get_historical_root_hashes()[-1][1] !=
                    server.chain_head_db.get_historical_root_hashes()[-1][1]) or
                    not client._new_blocks_to_import.empty() or
                    not server._new_blocks_to_import.empty()
                 ):

                await asyncio.sleep(0.5)

        await asyncio.wait_for(wait_loop(), SYNC_TIMEOUT)

    def validation_function(base_db_1, base_db_2):
        ensure_blockchain_databases_identical(base_db_1, base_db_2)

        #In this case they are valid blocks so we expect them to match the database where the blocks came from
        ensure_blockchain_databases_identical(base_db_1, expected_db)

    await _test_sync_with_variable_sync_parameters(request,
                                                   event_loop,
                                                   client_db,
                                                   server_db,
                                                   validation_function=validation_function,
                                                   waiting_function=waiting_function,
                                                   blocks_to_import=new_blocks,
                                                   blocks_to_import_from_rpc = simulate_importing_from_rpc)

@pytest.mark.asyncio
async def test_import_valid_block(request, event_loop):

    simulate_importing_from_rpc = False
    # Blocks with timestamps before time.time() - ADDITIVE_SYNC_MODE_CUTOFF should be rejected.
    new_tx_time = int(time.time() - ADDITIVE_SYNC_MODE_CUTOFF/2)

    tx_list = [[GENESIS_PRIVATE_KEY, RECEIVER, 100, new_tx_time]]
    new_blocks_db = get_fresh_db()
    add_transactions_to_blockchain_db(new_blocks_db, tx_list)

    expect_blocks_to_import = True

    node_new_blocks = MainnetChain(new_blocks_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    new_blocks = node_new_blocks.get_all_chronological_blocks_for_window(int((new_tx_time)/TIME_BETWEEN_HEAD_HASH_SAVE)*TIME_BETWEEN_HEAD_HASH_SAVE)

    await _setup_test_import_blocks(request,
                                    event_loop,
                                    new_blocks_db,
                                    new_blocks,
                                    simulate_importing_from_rpc,
                                    expect_blocks_to_import = expect_blocks_to_import)

@pytest.mark.asyncio
async def test_import_block_with_expired_timestamp(request, event_loop):

    simulate_importing_from_rpc = False
    # Blocks with timestamps before time.time() - ADDITIVE_SYNC_MODE_CUTOFF-TIME_BETWEEN_HEAD_HASH_SAVE should be rejected.
    new_tx_time = int(time.time() - ADDITIVE_SYNC_MODE_CUTOFF-TIME_BETWEEN_HEAD_HASH_SAVE-5)

    tx_list = [[GENESIS_PRIVATE_KEY, RECEIVER, 100, new_tx_time]]
    new_blocks_db = get_fresh_db()
    add_transactions_to_blockchain_db(new_blocks_db, tx_list)

    expect_blocks_to_import = False

    node_new_blocks = MainnetChain(new_blocks_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    new_blocks = node_new_blocks.get_all_chronological_blocks_for_window(int((new_tx_time)/TIME_BETWEEN_HEAD_HASH_SAVE)*TIME_BETWEEN_HEAD_HASH_SAVE)

    await _setup_test_import_blocks(request,
                                    event_loop,
                                    new_blocks_db,
                                    new_blocks,
                                    simulate_importing_from_rpc,
                                    expect_blocks_to_import = expect_blocks_to_import)

@pytest.mark.asyncio
async def test_import_block_with_low_gas(request, event_loop):

    simulate_importing_from_rpc = False
    # Blocks with timestamps before time.time() - ADDITIVE_SYNC_MODE_CUTOFF-TIME_BETWEEN_HEAD_HASH_SAVE should be rejected.
    new_tx_time = int(time.time() - ADDITIVE_SYNC_MODE_CUTOFF/2)

    tx_list = [[GENESIS_PRIVATE_KEY, RECEIVER, 100, new_tx_time]]
    new_blocks_db = get_fresh_db()
    add_transactions_to_blockchain_db(new_blocks_db, tx_list)

    expect_blocks_to_import = False

    node_new_blocks = MainnetChain(new_blocks_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    new_blocks = node_new_blocks.get_all_chronological_blocks_for_window(int((new_tx_time)/TIME_BETWEEN_HEAD_HASH_SAVE)*TIME_BETWEEN_HEAD_HASH_SAVE)

    await _setup_test_import_blocks(request,
                                    event_loop,
                                    new_blocks_db,
                                    new_blocks,
                                    simulate_importing_from_rpc,
                                    expect_blocks_to_import = expect_blocks_to_import,
                                    node_min_gas_price = 100)

@pytest.mark.asyncio
async def test_import_block_with_high_gas(request, event_loop):

    simulate_importing_from_rpc = False
    # Blocks with timestamps before time.time() - ADDITIVE_SYNC_MODE_CUTOFF-TIME_BETWEEN_HEAD_HASH_SAVE should be rejected.
    new_tx_time = int(time.time() - ADDITIVE_SYNC_MODE_CUTOFF/2)

    tx_list = [[GENESIS_PRIVATE_KEY, RECEIVER, 100, new_tx_time, 101]]
    new_blocks_db = get_fresh_db()
    add_transactions_to_blockchain_db(new_blocks_db, tx_list)

    expect_blocks_to_import = True

    node_new_blocks = MainnetChain(new_blocks_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    new_blocks = node_new_blocks.get_all_chronological_blocks_for_window(int((new_tx_time)/TIME_BETWEEN_HEAD_HASH_SAVE)*TIME_BETWEEN_HEAD_HASH_SAVE)

    await _setup_test_import_blocks(request,
                                    event_loop,
                                    new_blocks_db,
                                    new_blocks,
                                    simulate_importing_from_rpc,
                                    expect_blocks_to_import = expect_blocks_to_import,
                                    node_min_gas_price = 100)



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

async def wait_for_chain_head_hash(chain_head_db, expected_head_hash, at_timestamp):
    # A full header sync may involve several round trips, so we must be willing to wait a little
    # bit for them.
    HEADER_SYNC_TIMEOUT = 1000

    async def wait_loop():
        while expected_head_hash != chain_head_db.get_historical_root_hash(at_timestamp):
            #print("Waiting for db's to sync. Expected root hash = ", expected_head_hash, "actual root hash = ", chain_head_db.get_historical_root_hashes()[-1][1])
            await asyncio.sleep(0.1)
    await asyncio.wait_for(wait_loop(), HEADER_SYNC_TIMEOUT)


async def wait_for_both_nodes_to_be_synced(chain_head_db_1, chain_head_db_2):
    # A full header sync may involve several round trips, so we must be willing to wait a little
    # bit for them.
    HEADER_SYNC_TIMEOUT = 1000
    async def wait_loop():
        while chain_head_db_1.get_historical_root_hashes()[-1][1] != chain_head_db_2.get_historical_root_hashes()[-1][1]:
            #print("Waiting for db's to sync. Expected root hash = ", expected_head_hash, "actual root hash = ", chain_head_db.get_historical_root_hashes()[-1][1])
            # print(chain_head_db_1.get_historical_root_hashes()[-5:])
            # print(chain_head_db_2.get_historical_root_hashes()[-5:])
            # next_head_hashes_1 = chain_head_db_1.get_head_block_hashes_list()
            # next_head_hashes_2 = chain_head_db_2.get_head_block_hashes_list()
            # head_block_hashes_list_in_agreement = (next_head_hashes_1 == next_head_hashes_2)
            # print("waiting for db's to sync. Are head block hashes in agreement? {}".format(head_block_hashes_list_in_agreement))
            await asyncio.sleep(0.2)
    await asyncio.wait_for(wait_loop(), HEADER_SYNC_TIMEOUT)


class fake_request_object():
    def addfinalizer(dummy):
        pass

# if __name__ == "__main__":
#     __spec__ = 'None'
#     loop = asyncio.get_event_loop()
#     test_regular_syncer(fake_request_object(), loop)