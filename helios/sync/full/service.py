import logging
import time

from cancel_token import CancelToken

from hvm.chains import AsyncChain
from hvm.constants import BLANK_ROOT_HASH

from hp2p.service import BaseService

from helios.db.base import AsyncBaseDB
from helios.db.chain import AsyncChainDB
from helios.db.chain_head import AsyncChainHeadDB
from helios.protocol.hls.peer import HLSPeerPool
from helios.protocol.common.context import ChainContext

from .chain import FastChainSyncer, RegularChainSyncer

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hp2p.consensus import Consensus
    from helios.nodes.full import FullNode


class FullNodeSyncer(BaseService):
    chain: AsyncChain = None
    chaindb: AsyncChainDB = None
    chain_head_db: AsyncChainHeadDB = None
    base_db: AsyncBaseDB = None
    peer_pool: HLSPeerPool = None

    def __init__(self,
                 context: ChainContext,
                 peer_pool: HLSPeerPool,
                 consensus: 'Consensus',
                 node: 'FullNode',
                 token: CancelToken = None) -> None:
        super().__init__(token)
        self.context = context
        self.node = node
        self.consensus = consensus
        self.chain = context.chain
        self.chaindb = context.chaindb
        self.chain_head_db = context.chain_head_db
        self.base_db = context.base_db
        self.peer_pool = peer_pool

    async def _run(self) -> None:
        latest_chain_head_root_timestamp = self.chain_head_db.get_latest_timestamp()
        # We're still too slow at block processing, so if our local head is older than
        # FAST_SYNC_CUTOFF we first do a fast-sync run to catch up with the rest of the network.
        # See https://github.com/ethereum/py-evm/issues/654 for more details
        # if latest_chain_head_root_timestamp < time.time() - FAST_SYNC_CUTOFF:
        #     # Fast-sync chain data.
        #     self.logger.info("Starting fast-sync; current head: #%d", head.block_number)
        #     fast_syncer = FastChainSyncer(
        #         self.chain,
        #         self.chaindb,
        #         self.peer_pool,
        #         self.cancel_token,
        #     )
        #     await fast_syncer.run()
        #     # remove the reference so the memory can be reclaimed
        #     del fast_syncer
        #
        # if self.cancel_token.triggered:
        #     return

        # context: ChainContext,
        # peer_pool: HLSPeerPool,
        # consensus,
        # node,

        # Now, loop forever, fetching missing blocks and applying them.
        self.logger.info("Starting regular sync; latest root hash timestamp = {}".format(self.chain_head_db.get_latest_timestamp()))
        regular_syncer = RegularChainSyncer(context = self.context,
                                            peer_pool = self.peer_pool,
                                            consensus = self.consensus,
                                            node = self.node)
        await regular_syncer.run()


def _test() -> None:
    import argparse
    import asyncio
    import signal
    from hvm.chains.ropsten import RopstenChain, ROPSTEN_VM_CONFIGURATION
    from hvm.db.backends.level import LevelDB
    from hp2p import ecies
    from hp2p.kademlia import Node
    from helios.protocol.common.constants import DEFAULT_PREFERRED_NODES
    from helios.protocol.common.context import ChainContext
    from tests.helios.core.integration_test_helpers import (
        FakeAsyncChainDB, FakeAsyncRopstenChain, connect_to_peers_loop)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

    parser = argparse.ArgumentParser()
    parser.add_argument('-db', type=str, required=True)
    parser.add_argument('-enode', type=str, required=False, help="The enode we should connect to")
    args = parser.parse_args()

    chaindb = FakeAsyncChainDB(LevelDB(args.db))
    chain = FakeAsyncRopstenChain(chaindb)
    network_id = RopstenChain.network_id
    privkey = ecies.generate_privkey()

    context = ChainContext(
        headerdb=chaindb,
        network_id=network_id,
        vm_configuration=ROPSTEN_VM_CONFIGURATION
    )
    peer_pool = HLSPeerPool(privkey=privkey, context=context)
    if args.enode:
        nodes = tuple([Node.from_uri(args.enode)])
    else:
        nodes = DEFAULT_PREFERRED_NODES[network_id]
    asyncio.ensure_future(peer_pool.run())
    peer_pool.run_task(connect_to_peers_loop(peer_pool, nodes))

    loop = asyncio.get_event_loop()

    syncer = FullNodeSyncer(chain, chaindb, chaindb.db, peer_pool)

    sigint_received = asyncio.Event()
    for sig in [signal.SIGINT, signal.SIGTERM]:
        loop.add_signal_handler(sig, sigint_received.set)

    async def exit_on_sigint() -> None:
        await sigint_received.wait()
        await syncer.cancel()
        await peer_pool.cancel()
        loop.stop()

    loop.set_debug(True)
    asyncio.ensure_future(exit_on_sigint())
    asyncio.ensure_future(syncer.run())
    loop.run_forever()
    loop.close()


if __name__ == "__main__":
    _test()
