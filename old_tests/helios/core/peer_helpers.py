from cancel_token import CancelToken

from hvm.chains.mainnet import (
    MAINNET_GENESIS_HEADER,
)
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

from tests.helios.core.integration_test_helpers import FakeAsyncHeaderDB


def get_fresh_mainnet_headerdb():
    headerdb = FakeAsyncHeaderDB(AtomicDB())
    headerdb.persist_header(MAINNET_GENESIS_HEADER)
    return headerdb


async def _setup_alice_and_bob_factories(
        alice_headerdb=None, bob_headerdb=None,
        alice_peer_class=HLSPeer, bob_peer_class=None):
    if bob_peer_class is None:
        bob_peer_class = alice_peer_class

    cancel_token = CancelToken('helios.get_directly_linked_peers_without_handshake')

    #
    # Alice
    #
    if alice_headerdb is None:
        alice_headerdb = get_fresh_mainnet_headerdb()

    alice_context = ChainContext(
        headerdb=alice_headerdb,
        network_id=1,
        vm_configuration=tuple(),
    )

    if alice_peer_class is HLSPeer:
        alice_factory_class = HLSPeerFactory
    elif alice_peer_class is LESPeer:
        alice_factory_class = LESPeerFactory
    else:
        raise TypeError(f"Unknown peer class: {alice_peer_class}")

    alice_factory = alice_factory_class(
        privkey=ecies.generate_privkey(),
        context=alice_context,
        token=cancel_token,
    )

    #
    # Bob
    #
    if bob_headerdb is None:
        bob_headerdb = get_fresh_mainnet_headerdb()

    bob_context = ChainContext(
        headerdb=bob_headerdb,
        network_id=1,
        vm_configuration=tuple(),
    )

    if bob_peer_class is HLSPeer:
        bob_factory_class = HLSPeerFactory
    elif bob_peer_class is LESPeer:
        bob_factory_class = LESPeerFactory
    else:
        raise TypeError(f"Unknown peer class: {bob_peer_class}")

    bob_factory = bob_factory_class(
        privkey=ecies.generate_privkey(),
        context=bob_context,
        token=cancel_token,
    )

    return alice_factory, bob_factory


async def get_directly_linked_peers_without_handshake(
        alice_headerdb=None, bob_headerdb=None,
        alice_peer_class=HLSPeer, bob_peer_class=None):
    alice_factory, bob_factory = await _setup_alice_and_bob_factories(
        alice_headerdb, bob_headerdb,
        alice_peer_class, bob_peer_class,
    )

    return await _get_directly_linked_peers_without_handshake(
        alice_factory=alice_factory,
        bob_factory=bob_factory,
    )


async def get_directly_linked_peers(
        request, event_loop,
        alice_headerdb=None, bob_headerdb=None,
        alice_peer_class=HLSPeer, bob_peer_class=None):
    alice_factory, bob_factory = await _setup_alice_and_bob_factories(
        alice_headerdb, bob_headerdb,
        alice_peer_class, bob_peer_class,
    )

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
