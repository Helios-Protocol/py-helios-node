import asyncio
import logging
import math
import operator
import time

from helios.db.chain_head import AsyncChainHeadDB
from lahja import Endpoint


from typing import (
    List,
    cast,
    Set,
    Type,
)
from hp2p.protocol import Command


from helios.rlp_templates.hls import (
    BlockHashKey,
    P2PBlock)

from helios.chains.coro import AsyncChain
from helios.db.consensus import AsyncConsensusDB

from hp2p import protocol

from helios.protocol.hls.commands import (
    UnorderedBlockHeaderHash,
)
from helios.protocol.common.context import ChainContext

from cancel_token import CancelToken

from hp2p.exceptions import (
    OperationCancelled,
)
from hp2p.peer import BasePeer, PeerSubscriber
from helios.protocol.hls.peer import HLSPeerPool

from helios.protocol.hls.peer import HLSPeer
from hp2p.service import BaseService

from helios.nodes.base import Node

from hp2p.events import NewBlockEvent

from eth_utils import encode_hex

from typing import TYPE_CHECKING

from helios.protocol.hls import commands

if TYPE_CHECKING:
    from hp2p.consensus import Consensus

class SmartContractChainManager(BaseService, PeerSubscriber):

    msg_queue_maxsize = 500
    subscription_msg_types: Set[Type[Command]] = {
        commands.UnorderedBlockHeaderHash,
    }


    logger = logging.getLogger("hp2p.SmartContractChainManager")


    def __init__(self,
                 context: ChainContext,
                 peer_pool: HLSPeerPool,
                 node,
                 consensus: 'Consensus',
                 event_bus: Endpoint = None,
                 token: CancelToken = None) -> None:
        super().__init__(token)
        self.node: Node = node
        self.consensus = consensus
        self.event_bus = event_bus
        self.chaindb = context.chaindb
        self.base_db = context.base_db
        self.consensus_db: AsyncConsensusDB = context.consensus_db
        self.chain_head_db: AsyncChainHeadDB = context.chain_head_db
        self.peer_pool = peer_pool
        self.chain_config = context.chain_config

        self.chain = self.node.get_new_chain(chain_address = self.chain_config.node_wallet_address,
                                             private_key = self.chain_config.node_private_helios_key)

     
    #
    # Properties and utils
    #

    #
    # Loopers
    #
    async def _handle_msg_loop(self) -> None:
        while self.is_running:
            try:
                peer, cmd, msg = await self.wait(self.msg_queue.get())
            except OperationCancelled:
                break

            # Our handle_msg() method runs cpu-intensive tasks in sub-processes so that the main
            # loop can keep processing msgs, and that's why we use ensure_future() instead of
            # awaiting for it to finish here.
            # self.logger.debug("received cmd, msg {}, {}".format(cmd, msg))
            asyncio.ensure_future(self.handle_msg(peer, cmd, msg))

    async def handle_msg(self, peer: HLSPeer, cmd: protocol.Command,
                         msg: protocol._DecodedMsgType) -> None:
        try:
            await self._handle_msg(peer, cmd, msg)
        except OperationCancelled:
            # Silently swallow OperationCancelled exceptions because we run unsupervised (i.e.
            # with ensure_future()). Our caller will also get an OperationCancelled anyway, and
            # there it will be handled.
            pass
        except Exception:
            self.logger.exception("Unexpected error when processing msg from %s", peer)


    #
    # Standard service functions
    #
    def register_peer(self, peer: BasePeer) -> None:
        pass

    async def _run(self) -> None:

        self.run_daemon_task(self._handle_msg_loop())

        self.logger.debug('Waiting for consensus to be ready before starting smart contract manager')

        consensus_ready = await self.consensus.coro_is_ready.wait()

        if consensus_ready:
            with self.subscribe(self.peer_pool):
                await self.block_creation_loop()


    async def _cleanup(self) -> None:
        # We don't need to cancel() anything, but we yield control just so that the coroutines we
        # run in the background notice the cancel token has been triggered and return.
        await asyncio.sleep(0)


    #
    # Main functionality
    #
    async def block_creation_loop(self):
        while self.is_operational:
            self.logger.debug("Start of block creation loop")
            if await self.consensus.current_sync_stage >= 4:

                chain_addresses = self.chain.get_vm().state.account_db.get_smart_contracts_with_pending_transactions()
                for chain_address in chain_addresses:
                    # 1) Add the new block, 2) Propogate it to the network
                    # need to create a new chain to avoid conflicts with multiple processes
                    chain = self.node.get_new_private_chain(chain_address)
                    chain.populate_queue_block_with_receive_tx()

                    self.logger.debug("Importing new block on smart contract chain {}".format(encode_hex(chain_address)))

                    new_block = await chain.coro_import_current_queue_block()

                    self.logger.debug("Sending new smart contract block to network")

                    self.event_bus.broadcast(
                        NewBlockEvent(block=cast(P2PBlock, new_block),
                                      only_propogate_to_network=True)
                    )

                    self.logger.debug("Successfully updated smart contract chain")


            await asyncio.sleep(1)


    #
    # message handling stuff
    #
    async def _handle_msg(self, peer: HLSPeer, cmd: protocol.Command,
                          msg: protocol._DecodedMsgType) -> None:
        #TODO: change these to use something else other than isinstance. Check the command id and offset maybe?
        pass
        # if isinstance(cmd, UnorderedBlockHeaderHash):
        #     await self._handle_block_choices(peer, cast(List[BlockHashKey], msg))

            

            
            
            
            
            
            