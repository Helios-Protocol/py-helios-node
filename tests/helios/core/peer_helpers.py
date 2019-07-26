from cancel_token import CancelToken

from hvm.db.atomic import AtomicDB

from hp2p import ecies
from hp2p.tools.paragon.helpers import (
    get_directly_linked_peers_without_handshake as _get_directly_linked_peers_without_handshake,
    get_directly_linked_peers as _get_directly_linked_peers,
)


from helios.protocol.common.context import ChainContext

from helios.protocol.hls.peer import (
    HLSPeer,
    HLSPeerFactory,
    HLSPeerPool,
)
from helios.protocol.les.peer import (
    LESPeer,
    LESPeerFactory,
)

from hvm import MainnetChain

from tests.helios.core.integration_test_helpers import (
    FakeAsyncChainDB,
    get_fresh_db,
    FakeAsyncTestnetChain,
    FakeAsyncChainHeadDB,
    FakeAsyncConsensusDB
)

from helios.config import (
    ChainConfig,
)


from hvm.chains.testnet import (
    TESTNET_NETWORK_ID,
)

from eth_account import Account

from eth_keys import keys

def generate_random_private_key():
    priv_key_bytes = Account.create().privateKey
    return keys.PrivateKey(priv_key_bytes)

def get_chain_context(base_db, privkey):
    chain = FakeAsyncTestnetChain(base_db, privkey.public_key.to_canonical_address(), privkey)
    chaindb = FakeAsyncChainDB(base_db)
    chain_head_db = FakeAsyncChainHeadDB.load_from_saved_root_hash(base_db)
    consensus_db = FakeAsyncConsensusDB(chaindb)

    chain_config = ChainConfig(network_id=TESTNET_NETWORK_ID)
    chain_config._node_private_helios_key = privkey
    chain_config.num_chain_processes = 1

    network_id = TESTNET_NETWORK_ID
    vm_configuration = tuple()

    chain_context = ChainContext(
        base_db=base_db,
        chains = [chain],
        chaindb = chaindb,
        chain_head_db = chain_head_db,
        consensus_db = consensus_db,
        chain_config = chain_config,
        network_id = network_id,
        vm_configuration = vm_configuration,
    )
    return chain_context


def get_fresh_chain_context(privkey):
    base_db = get_fresh_db()
    return get_chain_context(base_db, privkey)

def get_fresh_testnet_chaindb():
    fresh_db = get_fresh_db()
    chaindb = FakeAsyncChainDB(fresh_db)
    return chaindb

async def _setup_alice_and_bob_factories(
        alice_db=None, bob_db=None):

    cancel_token = CancelToken('helios.get_directly_linked_peers_without_handshake')

    #
    # Alice
    #
    if alice_db is None:
        alice_db = get_fresh_db()


    alice_context = get_chain_context(alice_db, generate_random_private_key())

    alice_factory_class = HLSPeerFactory

    alice_factory = alice_factory_class(
        privkey=ecies.generate_privkey(),
        context=alice_context,
        token=cancel_token,
    )

    #
    # Bob
    #
    if bob_db is None:
        bob_db = get_fresh_db()

    bob_context = get_chain_context(bob_db, generate_random_private_key())

    bob_factory_class = HLSPeerFactory

    bob_factory = bob_factory_class(
        privkey=ecies.generate_privkey(),
        context=bob_context,
        token=cancel_token,
    )

    return alice_factory, bob_factory



async def get_directly_linked_peers_without_handshake(
        alice_db=None, bob_db=None):
    alice_factory, bob_factory = await _setup_alice_and_bob_factories(
        alice_db, bob_db
    )

    return await _get_directly_linked_peers_without_handshake(
        alice_factory=alice_factory,
        bob_factory=bob_factory,
    )


async def get_directly_linked_peers(
        request, event_loop,
        alice_db=None, bob_db=None,
        alice_private_helios_key = None, bob_private_helios_key = None):
    alice_factory, bob_factory = await _setup_alice_and_bob_factories(
        alice_db, bob_db,
    )

    # Set their private keys before doing the handshake
    if alice_private_helios_key is not None:
        alice_factory.context.chain_config._node_private_helios_key = alice_private_helios_key

    if bob_private_helios_key is not None:
        bob_factory.context.chain_config._node_private_helios_key = bob_private_helios_key

    return await _get_directly_linked_peers(
        request, event_loop,
        alice_factory=alice_factory,
        bob_factory=bob_factory,
    )


class MockPeerPoolWithConnectedPeers(HLSPeerPool):
    def __init__(self, peers) -> None:
        super().__init__(privkey=None, context=None)
        for peer in peers:
            self.connected_nodes[peer.remote] = peer

    async def _run(self) -> None:
        raise NotImplementedError("This is a mock PeerPool implementation, you must not _run() it")
