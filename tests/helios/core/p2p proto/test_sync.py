import asyncio
import logging

import pytest

from eth_keys import keys
from eth_utils import decode_hex

from hp2p.consensus import Consensus
from hvm import constants
from hvm.vm.forks.helios_testnet import HeliosTestnetVM
from tests.hvm.helios_logging import (
    setup_helios_logging,
)

from helios.sync.full.chain import RegularChainSyncer

from tests.helios.core.integration_test_helpers import (
    FakeAsyncMainnetChain,
    FakeAsyncChainDB,
    FakeAsyncAtomicDB,
    get_random_blockchain_db, get_fresh_db,
    FakeMainnetFullNode,
    MockConsensusService,
    get_random_long_time_blockchain_db)
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

log_level = getattr(logging, 'DEBUG')
logger, log_queue, listener = setup_helios_logging(log_level)
logger.propagate = False


# This causes the chain syncers to request/send small batches of things, which will cause us to
# exercise parts of the code that wouldn't otherwise be exercised if the whole sync was completed
# by requesting a single batch.
# @pytest.fixture(autouse=True)
# def small_header_batches(monkeypatch):
#     from helios.protocol.hls import constants
#     monkeypatch.setattr(constants, 'MAX_HEADERS_FETCH', 10)
#     monkeypatch.setattr(constants, 'MAX_BODIES_FETCH', 5)


# The server peer has the random db, and is also a bootnode.
@pytest.mark.asyncio
async def test_fast_syncer(request, event_loop, db_fresh, db_random_long_time):
    client_peer, server_peer = await get_directly_linked_peers(
        request, event_loop,
        alice_db=db_fresh,
        bob_db=db_random_long_time)

    client_node = FakeMainnetFullNode(
        base_db = client_peer.context.base_db,
        priv_key = client_peer.context.chain.private_key,
    )

    client_peer_pool = MockPeerPoolWithConnectedPeers([client_peer])

    # lets do a fast sync to newest root hash timestamp
    server_newest_root_hash_timestamp = server_peer.chain_head_db.get_historical_root_hashes()[-1]
    client_newest_root_hash_timestamp = client_peer.chain_head_db.get_historical_root_hashes()[-1]


    client_sync_parameters = SyncParameters(server_newest_root_hash_timestamp[0],
                                            client_newest_root_hash_timestamp[1],
                                            server_newest_root_hash_timestamp[1],
                                            [client_peer],
                                            FAST_SYNC_STAGE_ID)

    client_consensus = MockConsensusService(client_sync_parameters)

    client = RegularChainSyncer(
        context = client_peer.context,
        peer_pool = client_peer_pool,
        consensus = client_consensus,
        node = client_node,
    )

    server_node = FakeMainnetFullNode(
        base_db=server_peer.context.base_db,
        priv_key=server_peer.context.chain.private_key,
    )

    server_peer_pool = MockPeerPoolWithConnectedPeers([server_peer])

    server_consensus = MockConsensusService()

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

    #await client.run()
    await wait_for_chain_head_hash(client.chain_head_db, server.chain_head_db.get_historical_root_hashes()[-1][1])

    client_chain_head_hash = client.chain_head_db.get_historical_root_hashes()[-1][1]
    server_chain_head_hash = server.chain_head_db.get_historical_root_hashes()[-1][1]
    assert(client_chain_head_hash == server_chain_head_hash)


@pytest.fixture
def db_fresh():
    return get_fresh_db()

@pytest.fixture
def db_random():
    return get_random_blockchain_db()

@pytest.fixture
def db_random_long_time(length_in_centiseconds = 50):
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

async def wait_for_chain_head_hash(chain_head_db, expected_head_hash):
    # A full header sync may involve several round trips, so we must be willing to wait a little
    # bit for them.
    HEADER_SYNC_TIMEOUT = 1000

    async def wait_loop():
        while expected_head_hash != chain_head_db.get_historical_root_hashes()[-1][1]:
            print("Waiting for db's to sync. Expected root hash = ", expected_head_hash, "actual root hash = ", chain_head_db.get_historical_root_hashes()[-1][1])
            await asyncio.sleep(0.1)
    await asyncio.wait_for(wait_loop(), HEADER_SYNC_TIMEOUT)


async def wait_for_head(headerdb, header):
    # A full header sync may involve several round trips, so we must be willing to wait a little
    # bit for them.
    HEADER_SYNC_TIMEOUT = 3

    async def wait_loop():
        while headerdb.get_canonical_head() != header:
            await asyncio.sleep(0.1)
    await asyncio.wait_for(wait_loop(), HEADER_SYNC_TIMEOUT)


class fake_request_object():
    def addfinalizer(dummy):
        pass

# if __name__ == "__main__":
#     __spec__ = 'None'
#     loop = asyncio.get_event_loop()
#     test_regular_syncer(fake_request_object(), loop)