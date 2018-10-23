import asyncio
from asyncio import (
    PriorityQueue,
)

import time
from random import shuffle

from lahja import Endpoint

from hp2p.events import NewBlockEvent

from hvm.utils.blocks import get_block_average_transaction_gas_price

from hvm.exceptions import (
    HeaderNotFound,
    SyncerOutOfOrder,
    LocalRootHashNotAsExpected,
    CanonicalHeadNotFound,
    ReplacingBlocksNotAllowed,
    ParentNotFound,
    ValidationError,
)

from hp2p.constants import (
    FAST_SYNC_CUTOFF_PERIOD,
    NUM_CHAINS_TO_REQUEST,
    REPLY_TIMEOUT,
    CONSENSUS_SYNC_TIME_PERIOD,
    MOVING_WINDOW_WHERE_HISTORICAL_ROOT_HASH_NOT_SYNCED,
)

from hp2p.exceptions import (
    OperationCancelled,
    DatabaseResyncRequired,
)
from helios.rlp_templates.hls import (
    BlockBody,
    P2PTransaction,
    P2PBlock
)


from typing import (
    Any,
    Dict,
    List,
    Set,
    Tuple,
    Type,
    Union,
    cast,
    Optional,
    NamedTuple,
    Iterable,
)

from cancel_token import CancelToken, OperationCancelled
from eth_typing import Hash32, BlockNumber, Address
from eth_utils import (
    ValidationError,
    encode_hex,
)

from hvm.constants import (
    BLANK_ROOT_HASH,
    EMPTY_UNCLE_HASH,
    GENESIS_PARENT_HASH,
    NUMBER_OF_HEAD_HASH_TO_SAVE,
    TIME_BETWEEN_HEAD_HASH_SAVE,
    ZERO_HASH32,
)
from hvm.rlp.headers import BlockHeader
from hvm.rlp.receipts import Receipt

from hp2p import protocol
from hp2p.protocol import Command

from helios.protocol.hls import commands
from helios.protocol.hls.peer import HLSPeer, HLSPeerPool
from helios.protocol.les.peer import LESPeer
from helios.rlp_templates.hls import BlockBody
from helios.utils.datastructures import (
    SortableTask,
)

from hp2p.consensus import Consensus

from hp2p.peer import BasePeer, PeerSubscriber
from hp2p.service import BaseService
from helios.protocol.common.context import ChainContext
from hp2p.consensus import BlockConflictChoice

from sortedcontainers import (
    SortedDict,
    SortedList
)

from helios.db.base import AsyncBaseDB
from helios.db.chain import AsyncChainDB
from helios.db.chain_head import AsyncChainHeadDB
from hvm.chains import AsyncChain

HeaderRequestingPeer = Union[LESPeer, HLSPeer]
# (ReceiptBundle, (Receipt, (root_hash, receipt_trie_data))
ReceiptBundle = Tuple[Tuple[Receipt, ...], Tuple[Hash32, Dict[Hash32, bytes]]]
# (BlockBody, (txn_root, txn_trie_data), uncles_hash)
BlockBodyBundle = Tuple[
    BlockBody,
    Tuple[Hash32, Dict[Hash32, bytes]],
    Hash32,
]

# How big should the pending request queue get, as a multiple of the largest request size
REQUEST_BUFFER_MULTIPLIER = 8


class WaitingPeers:
    """
    Peers waiting to perform some action. When getting a peer from this queue,
    prefer the peer with the best throughput for the given command.
    """
    _waiting_peers: 'PriorityQueue[SortableTask[HLSPeer]]'

    def __init__(self, response_command_type: Type[Command]) -> None:
        self._waiting_peers = PriorityQueue()
        self._response_command_type = response_command_type
        self._peer_wrapper = SortableTask.orderable_by_func(self._ranked_peer)

    def _ranked_peer(self, peer: HLSPeer) -> float:
        relevant_throughputs = [
            exchange.tracker.items_per_second_ema.value
            for exchange in peer.requests
            if exchange.response_cmd_type == self._response_command_type
        ]

        if len(relevant_throughputs) == 0:
            raise ValidationError(
                f"Could not find any exchanges on {peer} "
                f"with response {self._response_command_type!r}"
            )

        avg_throughput = sum(relevant_throughputs) / len(relevant_throughputs)

        # high throughput peers should pop out of the queue first, so ranked as negative
        return -1 * avg_throughput

    def put_nowait(self, peer: HLSPeer) -> None:
        self._waiting_peers.put_nowait(self._peer_wrapper(peer))

    async def get_fastest(self) -> HLSPeer:
        wrapped_peer = await self._waiting_peers.get()
        peer = wrapped_peer.original

        # make sure the peer has not gone offline while waiting in the queue
        while not peer.is_operational:
            # if so, look for the next best peer
            wrapped_peer = await self._waiting_peers.get()
            peer = wrapped_peer.original

        return peer


class ChainRequestInfo():
    def __init__(self, peer, head_root_timestamp, head_root_hash, head_hash_of_last_chain, window_start, window_length,
                 timestamp_sent):
        self.peer = peer
        self.head_root_timestamp = head_root_timestamp
        self.head_root_hash = head_root_hash
        self.head_hash_of_last_chain = head_hash_of_last_chain
        self.window_start = window_start
        self.window_length = window_length
        self.timestamp_sent = timestamp_sent


class FastChainSyncer(BaseService, PeerSubscriber):
    """
    Sync with the Ethereum network by fetching/storing block headers, bodies and receipts.

    Here, the run() method will execute the sync loop until our local head is the same as the one
    with the highest TD announced by any of our peers.
    """

    subscription_msg_types: Set[Type[Command]] = {
        commands.GetChainsSyncing,
        commands.Chain,
        commands.NewBlock,
        commands.GetChronologicalBlockWindow,
        commands.ChronologicalBlockWindow,
        commands.GetChainSegment,
        commands.GetBlocks,
    }



    msg_queue_maxsize = 500

    # We'll only sync if we are connected to at least min_peers_to_sync.
    min_peers_to_sync = 1
    # TODO: Instead of a fixed timeout, we should use a variable one that gets adjusted based on
    # the round-trip times from our download requests.
    _reply_timeout = 10
    current_syncing_root_timestamp = None
    current_syncing_root_hash = None
    head_hash_of_last_chain = ZERO_HASH32
    last_window_start = 0
    last_window_length = 0
    base_db: AsyncBaseDB
    chain: AsyncChain
    chaindb: AsyncChainDB
    chain_head_db: AsyncChainHeadDB


    def __init__(self,
                 context: ChainContext,
                 peer_pool: HLSPeerPool,
                 consensus: Consensus,
                 node,
                 event_bus: Endpoint = None,
                 token: CancelToken = None) -> None:
        super().__init__(token)
        self.node = node
        self.consensus = consensus

        self.event_bus = event_bus
        self.chain = context.chain
        self.chaindb = context.chaindb
        self.chain_head_db = context.chain_head_db
        self.base_db = context.base_db
        self.peer_pool = peer_pool
        self._syncing = False
        self._sync_complete = asyncio.Event()
        self._sync_requests: asyncio.Queue[HLSPeer] = asyncio.Queue()
        self._idle_peers: asyncio.Queue[HLSPeer] = asyncio.Queue()
        self._idle_peers_in_consensus: asyncio.Queue[HLSPeer] = asyncio.Queue()
        self._new_headers: asyncio.Queue[List[BlockHeader]] = asyncio.Queue()
        self._new_blocks_to_import: asyncio.Queue[List[NewBlockQueueItem]] = asyncio.Queue()
        # Those are used by our msg handlers and _download_block_parts() in order to track missing
        # bodies/receipts for a given chain segment.
        self._downloaded_receipts: asyncio.Queue[
            Tuple[HLSPeer, List[DownloadedBlockPart]]] = asyncio.Queue()  # noqa: E501
        self._downloaded_bodies: asyncio.Queue[
            Tuple[HLSPeer, List[DownloadedBlockPart]]] = asyncio.Queue()  # noqa: E501

        # [{peer_wallet_address: ChainRequestInfo},{peer_wallet_address: ChainRequestInfo}...]
        self.pending_chain_requests = {}
        self.failed_chain_requests = {}

        # [{peer_wallet_address: num_chains_received},{peer_wallet_address: num_chains_received}...]
        self.num_chains_returned_in_incomplete_requests = {}

        # number of chains ahead of the last chain we requested. Inclusive
        self.chain_request_num_ahead = 0

        self.syncer_initialized = asyncio.Event()
        self.received_final_chain = asyncio.Event()

        self.writing_chain_request_vars = asyncio.Lock()

        self.logger.debug('this node wallet address = {}'.format(self.consensus.chain_config.node_wallet_address))

    @property
    def is_ready_for_regular_syncer(self):
        '''
        Returns true if we are synced enough to go into regular chain syncer
        :return:
        '''
        latest_synced_timestamp = self.chain_head_db.get_latest_timestamp()
        return latest_synced_timestamp > (int(time.time()) - NUMBER_OF_HEAD_HASH_TO_SAVE * TIME_BETWEEN_HEAD_HASH_SAVE)

    def register_peer(self, peer: HLSPeer) -> None:
        #        self.logger.debug("Registering peer. Their root_hash_timestamps: {}, our current root hash: {}, and timestamp {}".format(peer.chain_head_root_hashes,
        #                                                                                                                                  self.current_syncing_root_hash,
        #                                                                                                                                  self.current_syncing_root_timestamp ))
        if self.current_syncing_root_timestamp is None:
            last_synced_timestamp, last_synced_root_hash = self.chain_head_db.get_last_complete_historical_root_hash()
            if last_synced_timestamp == None:
                self._idle_peers.put_nowait(peer)
                self.logger.debug("Added peer {} to non-consensus queue1".format(peer.wallet_address))
                return

            timestamp_to_check = last_synced_timestamp
            root_hash_to_check = last_synced_root_hash
        else:
            timestamp_to_check = self.current_syncing_root_timestamp
            root_hash_to_check = self.current_syncing_root_hash

        self.logger.debug("timestamp used for registering peer in consensus = {}".format(timestamp_to_check))
        if peer.chain_head_root_hashes is not None:
            peer_root_hash_timestamps = SortedDict(peer.chain_head_root_hashes)

            try:
                if (peer_root_hash_timestamps[timestamp_to_check] == root_hash_to_check):
                    self._idle_peers_in_consensus.put_nowait(peer)
                    self.logger.debug("Added peer {} to consensus queue2".format(peer.wallet_address))
                else:
                    self._idle_peers.put_nowait(peer)
                    self.logger.debug("Added peer {} to non-consensus queue3".format(peer.wallet_address))
                    self.logger.debug(
                        "our timestamp and root hash: {} {}".format(timestamp_to_check, root_hash_to_check))
                    self.logger.debug("their  root hash: {}".format(peer_root_hash_timestamps[timestamp_to_check]))
            except KeyError:
                # ours may be newer than theirs, but still matching. check their latest one and see if it matches
                if peer_root_hash_timestamps.values()[-1] == root_hash_to_check:
                    self._idle_peers_in_consensus.put_nowait(peer)
                    self.logger.debug("Added peer {} to consensus queue6".format(peer.wallet_address))
                else:
                    self._idle_peers.put_nowait(peer)
                    self.logger.debug("Added peer {} to non-consensus queue4".format(peer.wallet_address))
        else:
            self._idle_peers.put_nowait(peer)
            self.logger.debug("Added peer {} to non-consensus queue5".format(peer.wallet_address))

    def re_register_peers(self):
        peers = []
        # empty the two queues
        while True:
            try:
                peers.append(self._idle_peers_in_consensus.get_nowait())
            except asyncio.QueueEmpty:
                break

        while True:
            try:
                peers.append(self._idle_peers.get_nowait())
            except asyncio.QueueEmpty:
                break

        # then requeue them all again
        for peer in peers:
            self.register_peer(peer)

    async def _handle_msg_loop(self) -> None:
        while self.is_running:
            try:
                peer, cmd, msg = await self.wait(self.msg_queue.get())
            except OperationCancelled:
                break

            # Our handle_msg() method runs cpu-intensive tasks in sub-processes so that the main
            # loop can keep processing msgs, and that's why we use ensure_future() instead of
            # awaiting for it to finish here.
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

    async def _run(self) -> None:
        self.logger.debug("Starting chain. waiting for consensus and chain config to initialize.")
        self.run_task(self._handle_msg_loop())

        consensus_ready = await self.consensus.coro_is_ready.wait()
        if consensus_ready:
            self.logger.debug("consensus ready")
            sync_parameters_ready = await self.initialize_sync_parameters()
            if sync_parameters_ready:
                self.logger.debug("Syncing parameters set")
                with self.subscribe(self.peer_pool):
                    self.run_daemon_task(self.re_queue_timeout_peers())
                    while self.is_operational:
                        await self.wait_first(self.send_chain_requests(), self._sync_complete.wait())
                        # await self.send_chain_requests()

                        if self._sync_complete.is_set():
                            self.finalize_complete_fast_sync()
                            self.logger.info("fast sync complete")
                            return

    def finalize_complete_fast_sync(self):
        self.chain_head_db.initialize_historical_root_hashes(self.current_syncing_root_hash,
                                                             self.current_syncing_timestamp)

    # step 1) determine which root hash to sync too
    # step 2) connect to peers that have that root hash
    async def initialize_sync_parameters(self):
        while not self.syncer_initialized.is_set():
            if self.current_syncing_root_timestamp != None:
                if self.current_syncing_root_timestamp < int(
                        time.time()) - NUMBER_OF_HEAD_HASH_TO_SAVE * TIME_BETWEEN_HEAD_HASH_SAVE:
                    # it is too old, we have to choose a new one and restart the sync
                    self.current_syncing_root_timestamp, self.current_syncing_root_hash = await self.consensus.get_closest_root_hash_consensus(
                        int(time.time()) - FAST_SYNC_CUTOFF_PERIOD)
                    if self.current_syncing_root_timestamp is not None:
                        self.chain_head_db.set_current_syncing_info(self.current_syncing_root_timestamp,
                                                                    self.current_syncing_root_hash)

            else:
                # look it up from db
                syncing_info = self.chain_head_db.get_current_syncing_info()
                self.logger.debug("syncing_info: {}".format(syncing_info))
                if syncing_info == None:
                    self.current_syncing_root_timestamp, self.current_syncing_root_hash = await self.consensus.get_closest_root_hash_consensus(
                        int(time.time()) - FAST_SYNC_CUTOFF_PERIOD)
                    self.head_hash_of_last_chain = ZERO_HASH32
                    if self.current_syncing_root_timestamp is not None:
                        self.chain_head_db.set_current_syncing_info(self.current_syncing_root_timestamp,
                                                                    self.current_syncing_root_hash)


                else:
                    timestamp = syncing_info.timestamp
                    root_hash = syncing_info.head_root_hash
                    head_hash_of_last_chain = syncing_info.head_hash_of_last_chain

                    if timestamp < int(time.time()) - NUMBER_OF_HEAD_HASH_TO_SAVE * TIME_BETWEEN_HEAD_HASH_SAVE:
                        self.current_syncing_root_timestamp, self.current_syncing_root_hash = await self.consensus.get_closest_root_hash_consensus(
                            int(time.time()) - FAST_SYNC_CUTOFF_PERIOD)
                        if self.current_syncing_root_timestamp is not None:
                            self.chain_head_db.set_current_syncing_info(self.current_syncing_root_timestamp,
                                                                        self.current_syncing_root_hash)

                    else:
                        self.current_syncing_root_timestamp, self.current_syncing_root_hash, self.head_hash_of_last_chain = timestamp, root_hash, head_hash_of_last_chain

            if self.current_syncing_root_timestamp is not None:
                self.syncer_initialized.set()
            else:
                self.logger.debug("could not initialize sync parameters yet. waiting 5 seconds to try again")
                await asyncio.sleep(5)
        return True

    async def re_queue_timeout_peers(self):
        while not self._sync_complete.is_set() and self.is_running:
            with await self.writing_chain_request_vars:
                for chain_request_wallet_address, chain_request_info in self.pending_chain_requests.copy().items():
                    self.logger.debug("checking peer timeouts, chain_request_timestamp = {}, timeout time = {}".format(
                        chain_request_info.timestamp_sent, (int(time.time()) - self._reply_timeout)))
                    if chain_request_info.timestamp_sent < int(time.time()) - self._reply_timeout:
                        # delete the request
                        self.failed_chain_requests[chain_request_wallet_address] = chain_request_info
                        del (self.pending_chain_requests[chain_request_wallet_address])
                        # re-queue peer
                        self.register_peer(chain_request_info.peer)
                        self.logger.debug("Requeuing a peer")

            await asyncio.sleep(self._reply_timeout)

    # send a request to a peer asking for the next chain. if it is not found, then it must be older. it cant be newer because of how we initialized sync.

    async def send_chain_requests(self):
        while not self._sync_complete.is_set() and self.is_running:
            peer = await self.wait(self._idle_peers_in_consensus.get())
            if peer.is_running:
                self.logger.debug("Found a peer to send chain requests to")
            else:
                self.logger.info("%s disconnected, aborting sync", peer)
                break

            with await self.writing_chain_request_vars:
                # first check if any requests failed, and send them out again
                failed_chain_requests = list(self.failed_chain_requests.values())
                if len(failed_chain_requests) > 0:
                    shuffle(failed_chain_requests)
                    window_start = failed_chain_requests[0].window_start
                    window_length = failed_chain_requests[0].window_length
                    head_hash_of_last_chain = failed_chain_requests[0].head_hash_of_last_chain
                    del (self.failed_chain_requests[failed_chain_requests[0].peer.wallet_address])
                    self.logger.debug("Resending failed chain request")
                else:
                    if self.received_final_chain.is_set():
                        # only send new chain requests if we havent gotten to the final one, or if we are re-requesting a failed request.
                        break
                    self.last_window_start = self.last_window_start + self.last_window_length
                    window_start = self.last_window_start

                    self.last_window_length = NUM_CHAINS_TO_REQUEST
                    window_length = self.last_window_length

                    head_hash_of_last_chain = self.head_hash_of_last_chain
                self.logger.info(
                    "Sending chain request to {}, window_start {}, window_length {}".format(peer.wallet_address,
                                                                                            window_start,
                                                                                            window_length))

                new_chain_request_info = ChainRequestInfo(peer,
                                                          self.current_syncing_root_timestamp,
                                                          self.current_syncing_root_hash,
                                                          head_hash_of_last_chain,
                                                          window_start,
                                                          window_length,
                                                          timestamp_sent=int(time.time()))
                peer.sub_proto.send_get_chains_syncing(new_chain_request_info)
                self.pending_chain_requests[peer.wallet_address] = new_chain_request_info



    async def _cleanup(self) -> None:
        # We don't need to cancel() anything, but we yield control just so that the coroutines we
        # run in the background notice the cancel token has been triggered and return.
        await asyncio.sleep(0)

    async def _handle_msg(self, peer: HLSPeer, cmd: protocol.Command,
                          msg: protocol._DecodedMsgType) -> None:

        if isinstance(cmd, commands.GetChainsSyncing):
            await self._handle_get_chains_syncing(peer, cast(Dict[str, Any], msg))
        elif isinstance(cmd, commands.Chain):
            await self._handle_chain(peer, cast(Dict[str, Any], msg))
        else:
            # self.logger.debug("Ignoring %s message from %s: msg %r", cmd, peer, msg)
            pass


    async def _handle_get_chains_syncing(self,
                                         peer: HLSPeer,
                                         chain_request: Dict[str, Any]) -> None:
        self.logger.debug("Peer %s made chains syncing request: %s", peer.wallet_address, chain_request)

        next_head_hashes = await self.chain_head_db.coro_get_next_n_head_block_hashes(
            chain_request['head_hash_of_last_chain'],
            chain_request['window_start'],
            chain_request['window_length'],
            root_hash=chain_request['head_root_hash'])
        if len(next_head_hashes) < chain_request['window_length']:
            contains_last_chain = True
        else:
            contains_last_chain = False

        is_last_chain = False

        if next_head_hashes is not None:
            for head_hash in next_head_hashes:

                chain_address = await self.chaindb.coro_get_chain_wallet_address_for_block_hash(self.base_db, head_hash)
                # whole_chain = await self.chaindb.coro_get_all_blocks_on_chain(self.chain.get_vm().get_block_class(), chain_address)
                whole_chain = await self.chaindb.coro_get_all_blocks_on_chain(P2PBlock, chain_address)

                if contains_last_chain:
                    if head_hash == next_head_hashes[-1]:
                        is_last_chain = True

                peer.sub_proto.send_chain(whole_chain, is_last_chain)
                self.logger.debug(
                    "sending chain with chain address {}, is_last? {}".format(chain_address, is_last_chain))

    async def _handle_chain(self,
                            peer: HLSPeer,
                            msg: Dict[str, Any]) -> None:

        with await self.writing_chain_request_vars:
            try:
                num_chains_expected = self.pending_chain_requests[peer.wallet_address].window_length
                # update the timestamp so that it doesnt time out.
                self.pending_chain_requests[peer.wallet_address].timestamp_sent = int(time.time())
            except KeyError:
                self.logger.debug("was sent a chain that we didn't request")
                return

            try:
                num_chains_received = self.num_chains_returned_in_incomplete_requests[peer.wallet_address]
            except KeyError:
                num_chains_received = 0

            if num_chains_expected <= num_chains_received:
                self.logger.debug("was sent too many chains")
                return

            # now lets save it to database overwriting any chain that we have
            self.logger.debug("importing chain now")
            await self.chain.coro_import_chain(block_list=msg['blocks'], save_block_head_hash_timestamp=False)
            try:
                self.num_chains_returned_in_incomplete_requests[peer.wallet_address] += 1
            except KeyError:
                self.num_chains_returned_in_incomplete_requests[peer.wallet_address] = 1

            if self.num_chains_returned_in_incomplete_requests[peer.wallet_address] == num_chains_expected:
                del (self.pending_chain_requests[peer.wallet_address])
                del (self.num_chains_returned_in_incomplete_requests[peer.wallet_address])
                self.register_peer(peer)

            if msg['is_last'] == True:
                # if this is set, we won't receive any more chains from this peer
                # even if we havent received the number of chains we asked for
                del (self.pending_chain_requests[peer.wallet_address])
                self.received_final_chain.set()

                if len(self.pending_chain_requests) == 0:
                    self._sync_complete.set()


class RegularChainSyncer(FastChainSyncer):
    """
    Sync with the Ethereum network by fetching block headers/bodies and importing them.

    Here, the run() method will execute the sync loop forever, until our CancelToken is triggered.
    """
    _current_syncing_root_timestamp = None
    _current_syncing_root_hash = None
    _latest_block_conflict_choices_to_change = None

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._initial_sync_complete = asyncio.Event()
        # [(new_chronological_blocks, final_root_hash),...]
        self._new_chronological_block_window = asyncio.Queue()

        self.chain_head_db.load_saved_root_hash()

    async def _run(self) -> None:
        if self.is_ready_for_regular_syncer:

            self.logger.debug("Starting regular chainsyncer. waiting for consensus and chain config to initialize.")
            self.run_daemon_task(self._handle_msg_loop())
            consensus_ready = await self.consensus.coro_is_ready.wait()
            if consensus_ready:
                self.logger.debug('waiting for consensus min gas system ready')
                min_gas_system_ready = await self.consensus.coro_min_gas_system_ready.wait()
                if min_gas_system_ready:
                    self.logger.debug("consensus ready")
                    with self.subscribe(self.peer_pool):

                        self.logger.debug("syncing chronological blocks")
                        # await self.sync_chronological_blocks()

                        self.run_daemon_task(self._handle_import_block_loop())
                        if self.event_bus is not None:
                            self.run_task(self.handle_new_block_events())

                        # this runs forever
                        self.run_daemon_task(self.sync_historical_root_hash_with_consensus())
                        # asyncio.ensure_future(self.re_queue_timeout_peers())
                        await self.sync_block_conflict_with_consensus()

        else:
            self.logger.error(
                'We are not synced enough for regular chain syncer to start. Need to run fastchainsyncer first. '
                'If this is the genesis node, make sure the genesis block timestamp is within the regular syncer range.')

    async def _handle_msg_loop(self) -> None:
        while self.is_running:
            try:
                peer, cmd, msg = await self.wait(self.msg_queue.get())
            except OperationCancelled:
                break

            # Our handle_msg() method runs cpu-intensive tasks in sub-processes so that the main
            # loop can keep processing msgs, and that's why we use ensure_future() instead of
            # awaiting for it to finish here.
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

    async def _handle_import_block_loop(self):
        while self.is_running:
            try:
                new_block_queue_item = await self.wait(self._new_blocks_to_import.get())
            except OperationCancelled:
                break
            self.logger.debug('found new block to import in queue. sending to handling function')
            # we await for the import block function here to make sure that we are only importing one block at a time.
            # later we will add multiprocessing with multiple instances of this object to import in parallel.
            try:
                await self.handle_new_block(new_block=new_block_queue_item.new_block,
                                            chain_address=new_block_queue_item.chain_address,
                                            peer=new_block_queue_item.peer,
                                            propogate_to_network=new_block_queue_item.propogate_to_network,
                                            from_rpc=new_block_queue_item.from_rpc)
            except OperationCancelled:
                # Silently swallow OperationCancelled exceptions because we run unsupervised (i.e.
                # with ensure_future()). Our caller will also get an OperationCancelled anyway, and
                # there it will be handled.
                pass
            except Exception:
                self.logger.exception("Unexpected error when importing block from %s", new_block_queue_item.peer)


    async def sync_block_conflict_with_consensus(self):
        self.logger.debug("sync_block_conflict_with_consensus starting")
        while self.is_operational:
            self.logger.debug("sync_historical_root_hash_with_consensus loop start")
            block_conflict_choices_to_change = await self.consensus.get_correct_block_conflict_choice_where_we_differ_from_consensus()
            if block_conflict_choices_to_change is not None:
                # save this so that we know to replace our local block when this one is sent to us.
                self._latest_block_conflict_choices_to_change = set(block_conflict_choices_to_change)
                self.logger.debug("block conflict syncer found blocks that need changing.")

                for block_conflict_choice in block_conflict_choices_to_change:
                    peers_with_block = self.consensus.get_peers_who_have_conflict_block(
                        block_conflict_choice.block_hash)
                    peers_sorted_by_stake = self.peer_pool.sort_peers_by_stake(peers=peers_with_block)

                    self.logger.debug("asking a peer for the consensus version of a conflict block that we have")
                    peers_sorted_by_stake[-1].sub_proto.send_get_chain_segment(block_conflict_choice.chain_address,
                                                                               block_conflict_choice.block_number)

            await asyncio.sleep(CONSENSUS_SYNC_TIME_PERIOD)

    async def sync_historical_root_hash_with_consensus(self):
        self.logger.debug("sync_historical_root_hash_with_consensus starting")
        while True:
            self.logger.debug("sync_historical_root_hash_with_consensus loop start")
            # this loop can continuously look at the root hashes in consensus, if they dont match ours then we need to update to the new one
            # it also has to look at conflict blocks and make sure we always have the one that is in consensus.
            #            if not self._initial_sync_complete.is_set():
            #                self.logger.debug("within sync_with_consensus loop. _initial_sync_complete not set, so running sync_chronological_blocks")
            #                self.sync_chronological_blocks()

            try:
                consensus_root_hash, latest_good_timestamp = await self.consensus.get_latest_root_hash_before_conflict(
                    before_timestamp=time.time() - MOVING_WINDOW_WHERE_HISTORICAL_ROOT_HASH_NOT_SYNCED)
            except DatabaseResyncRequired:
                # genesis_header = self.chaindb.get_canonical_block_header_by_number(BlockNumber(0), Address(self.chain.get_genesis_wallet_address()))
                # if genesis_header.timestamp > int(time.time()) - TIME_BETWEEN_HEAD_HASH_SAVE * NUMBER_OF_HEAD_HASH_TO_SAVE:
                #     #None of our root hashes match, but the genesis is within regularsync window. So proceed with normal sync.
                #     self.logger.debug("Genesis block appears to be within regularsync window. Proceeding to sync.")
                #     consensus_root_hash = 'genesis'
                #     latest_good_timestamp = 0
                #     pass
                # else:
                # this means none of our root hashes match consensus. We need to delete our entire database and do fast sync again
                self.logger.error("Our database has been offline for too long. Need to perform fast sync again. Database should be deleted and program should be restarted. ")
                sys.exit()

            # this is the latest one where we actually do match consensus. Now we re-sync up to the next one

            if consensus_root_hash is None:
                # here we find that we have no conflict with the database that we currently have.
                # However, we havent checked to see if we have the most up to data database. Need to check here.
                last_synced_timestamp_local, _ = self.chain_head_db.get_latest_historical_root_hash()
                last_available_timestamp_from_peers = self.consensus.get_newest_peer_root_hash_timestamp()
                if last_available_timestamp_from_peers is None:
                    self.logger.debug("We have no peer root hashes to sync with")
                else:
                    if last_synced_timestamp_local < last_available_timestamp_from_peers:
                        self.logger.debug(
                            "local database is in consensus but not up to date. running sync_chronological_blocks")
                        self._initial_sync_complete.clear()
                        await self.sync_chronological_blocks()

                    # if it is none, then we have no conflicts
                    self.logger.debug("no conflicts found")
                await asyncio.sleep(CONSENSUS_SYNC_TIME_PERIOD)
            else:
                # We have conflicts, lets sync up one window, and let the loop continue to go through all windows
                # self.current_syncing_root_timestamp, self.current_syncing_root_hash = self.consensus.get_next_consensus_root_hash_after_timestamp_that_differs_from_local_at_timestamp(latest_good_timestamp)
                self.current_syncing_root_timestamp, self.current_syncing_root_hash = self.consensus.get_next_consensus_root_hash_after_timestamp(
                    latest_good_timestamp)

                self.logger.debug(
                    "Conflict found. Syncing historical window for time {}".format(self.current_syncing_root_timestamp))
                # re-queue all peers so that we know which ones are in consensus
                self.re_register_peers()

                try:
                    peer = await self.wait(self._idle_peers_in_consensus.get(), timeout=CONSENSUS_SYNC_TIME_PERIOD)
                except TimeoutError:
                    self.logger.debug('sync_with_consensus timeout because there are no peers in consensus')
                    continue

                if peer.is_running:
                    self.logger.debug(
                        "Found a peer to sync with for sync_with_consensus = {}".format(peer.wallet_address))
                else:
                    self.logger.info("%s disconnected, aborting sync with this peer", peer)
                    continue

                # make sure the peer has data for this timestamp. We may already be up to date, and there just havent been transactions for a while
                sorted_dict_root_hashes = SortedDict(peer.chain_head_root_hashes)
                peer_timestamps = list(sorted_dict_root_hashes.keys())
                if peer_timestamps[-1] < self.current_syncing_root_timestamp:
                    self.logger.debug(
                        "Skipping sync_with_consensus with this peer they dont have the correct root hash timestamp")
                    continue

                try:
                    # we sync the chronological window that leads up to the one we are syncing
                    await self.sync_chronological_window(
                        self.current_syncing_root_timestamp - TIME_BETWEEN_HEAD_HASH_SAVE, peer, new_window=False)
                except TimeoutError:
                    self.logger.debug('sync_chronological_blocks timeout')
                    self.register_peer(peer)
                    continue
                except LocalRootHashNotAsExpected:
                    self.register_peer(peer)
                    continue
                except Exception as e:
                    self.logger.debug('Uncaught exception {}'.format(e))
                    # there was an error importing the blocks. this most likely means one of the blocks was invalid.
                    # so lets re-request this block window from someone else.
                    self.register_peer(peer)
                    raise e
                    continue

                #                except Exception as e:
                #                    self.logger.debug('Uncaught exception {}'.format(e))
                #                    #there was an error importing the blocks. this most likely means one of the blocks was invalid.
                #                    #so lets re-request this block window from someone else.
                #                    self.register_peer(peer)
                #                    continue

                self.register_peer(peer)

    # run this once before running the main function that keeps our database up to date.
    # we cannot import new blocks while this is running because it will save a new root hash
    # TODO: on receive new block function, have a switch that checks if chronological blocks have run yet
    async def sync_chronological_blocks(self):
        while not self._initial_sync_complete.is_set() and self.is_running:

            last_synced_timestamp, last_synced_root_hash = self.chain_head_db.get_latest_historical_root_hash()
            # last_synced_timestamp, last_synced_root_hash = self.chain_head_db.get_last_complete_historical_root_hash()
            if last_synced_timestamp > time.time():
                self.logger.debug("finished chronological block sync 3")
                self._initial_sync_complete.set()
                return

            self.logger.debug(
                "{}, {}".format(last_synced_timestamp, self.consensus.get_newest_peer_root_hash_timestamp()))
            if last_synced_timestamp >= self.consensus.get_newest_peer_root_hash_timestamp():
                self.logger.debug("finished chronological block sync 2")
                self._initial_sync_complete.set()
                return

            timestamp_to_check_peer_consensus, root_hash_to_check_peer_consensus = self.consensus.get_next_consensus_root_hash_after_timestamp_that_differs_from_local_at_timestamp(
                last_synced_timestamp)

            self.current_syncing_root_timestamp, self.current_syncing_root_hash = timestamp_to_check_peer_consensus, root_hash_to_check_peer_consensus
            # re-register peers so we know which ones are in consensus

            self.re_register_peers()

            peer = await self.wait(self._idle_peers_in_consensus.get())
            if peer.is_running:
                self.logger.debug(
                    "Found a peer to send chronological block requests to. peer wallet address = {}".format(
                        peer.wallet_address))
            else:
                self.logger.info("%s disconnected, aborting sync with this peer", peer)
                continue

            # make sure the peer has data for this timestamp. We may already be up to date, and there just havent been transactions for a while
            sorted_list_root_hashes = SortedList(peer.chain_head_root_hashes)

            if sorted_list_root_hashes[-1][0] <= (self.current_syncing_root_timestamp - TIME_BETWEEN_HEAD_HASH_SAVE):
                self.logger.debug(
                    "Skipping chronological block sync with this peer because they don't have any newer blocks and dont match our latest imported window")
                continue
            try:
                await self.sync_chronological_window(self.current_syncing_root_timestamp - TIME_BETWEEN_HEAD_HASH_SAVE,
                                                     peer, new_window=True)
            except TimeoutError:
                self.logger.debug('sync_chronological_blocks timeout')
                self.register_peer(peer)
                continue
            except LocalRootHashNotAsExpected:
                self.register_peer(peer)
                continue
            except Exception as e:
                self.logger.debug('Uncaught exception {}'.format(e))
                # there was an error importing the blocks. this most likely means one of the blocks was invalid.
                # so lets re-request this block window from someone else.
                self.register_peer(peer)
                continue

            self.register_peer(peer)

    async def sync_chronological_window(self, window_start_timestamp, peer, new_window=False):
        # we can now download the chronological blocks for this window, and then save the root hash for the next window

        peer.sub_proto.send_get_chronological_block_window(window_start_timestamp)

        new_chronological_blocks, final_root_hash = await self.wait(
            self._new_chronological_block_window.get(),
            token=peer.cancel_token,
            timeout=self._reply_timeout)


        chain = self.node.get_new_chain()

        chain.import_chronological_block_window(new_chronological_blocks,
                                                window_start_timestamp=window_start_timestamp,
                                                save_block_head_hash_timestamp=True,
                                                allow_unprocessed=True)

        local_head_root_hash = self.chain_head_db.get_historical_root_hash(self.current_syncing_root_timestamp)
        #        full_root_hash_list = self.chain_head_db.get_historical_root_hashes(after_timestamp = self.current_syncing_root_timestamp-10000)
        #        self.logger.debug("here are the root hashes around that time {}".format(full_root_hash_list))
        if local_head_root_hash != final_root_hash:
            self.logger.debug(
                "root hash is not as expected after importing chronological block window for timestamp {}. will re-request window. local: {}, expected: {}".format(
                    window_start_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE, local_head_root_hash, final_root_hash))
            raise LocalRootHashNotAsExpected()

    async def _handle_msg(self, peer: HLSPeer, cmd: protocol.Command,
                          msg: protocol._DecodedMsgType) -> None:
        if isinstance(cmd, commands.NewBlock):
            await self._handle_new_block(peer, cast(Dict[str, Any], msg))
        elif isinstance(cmd, commands.GetChronologicalBlockWindow):
            await self._handle_get_chronological_block_window(peer, cast(Dict[str, Any], msg))
        elif isinstance(cmd, commands.ChronologicalBlockWindow):
            await self._handle_chronological_block_window(peer, cast(Dict[str, Any], msg))
        elif isinstance(cmd, commands.GetChainSegment):
            await self._handle_get_chain_segment(peer, cast(Dict[str, Any], msg))
        elif isinstance(cmd, commands.Chain):
            await self._handle_chain(peer, cast(Dict[str, Any], msg))
        elif isinstance(cmd, commands.GetBlocks):
            await self._handle_get_blocks(peer, cast(Iterable, msg))



    async def _handle_get_chronological_block_window(self, peer: HLSPeer, msg: Dict[str, Any]) -> None:
        self.logger.debug("_handle_get_chronological_block_window")

        start_timestamp = msg['start_timestamp']
        self.logger.debug("start_timestamp = {}".format(start_timestamp))
        final_root_hash = self.chain_head_db.get_historical_root_hash(start_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE)
        blocks_for_window = await self.chain.coro_get_all_chronological_blocks_for_window(start_timestamp)
        if blocks_for_window is None:
            if final_root_hash is not None:
                peer.sub_proto.send_chronological_block_window([], final_root_hash)
        else:
            peer.sub_proto.send_chronological_block_window(blocks_for_window, final_root_hash)

    async def _handle_chronological_block_window(self, peer: HLSPeer, msg: Dict[str, Any]) -> None:
        self.logger.debug("_handle_chronological_block_window, blocks: {}".format(msg['blocks']))
        #         class ChronologicalBlockWindow(Command):
        #            _cmd_id = 30
        #            structure = [
        #                ('blocks', sedes.CountableList(P2PBlock)),
        #                ('final_root_hash', hash32)]
        self._new_chronological_block_window.put_nowait((msg['blocks'], msg['final_root_hash']))




    async def _handle_get_chain_segment(self,
                                        peer: HLSPeer,
                                        msg: Dict[str, Any]) -> None:

        #        data = {
        #            'chain_address': chain_address,
        #            'block_number_start': block_number_start,
        #            'block_number_end': block_number_end,
        #            }

        self.logger.debug("Peer %s made chains segment request", encode_hex(peer.wallet_address))

        chain_address = msg['chain_address']

        # whole_chain = await self.chaindb.coro_get_all_blocks_on_chain(self.chain.get_vm().get_block_class(), chain_address)
        chain_segment = await self.chaindb.coro_get_blocks_on_chain(P2PBlock, msg['block_number_start'],
                                                                    msg['block_number_end'], chain_address)

        peer.sub_proto.send_chain(chain_segment, True)

        self.logger.debug("sending chain with chain address {}".format(chain_address))

    async def _handle_get_blocks(self,
                                        peer: HLSPeer,
                                        msg: Iterable) -> None:


        self.logger.debug("Peer %s made get_blocks request", encode_hex(peer.wallet_address))

        hashes = msg
        blocks_to_return = []
        for hash in hashes:
            try:
                new_block = cast(P2PBlock, await self.chaindb.coro_get_block_by_hash(hash, P2PBlock))
                blocks_to_return.append(new_block)
            except HeaderNotFound:
                pass

        if len(blocks_to_return) > 0:
            peer.sub_proto.send_blocks(blocks_to_return)

            self.logger.debug("Sent peer {} the blocks they requested".format(encode_hex(peer.wallet_address)))

    async def _handle_chain(self,
                            peer: HLSPeer,
                            msg: Dict[str, Any]) -> None:
        self.logger.debug("received new chain")
        block_list = msg['blocks']

        # in this mode, we can only import a chain if we already have the parent,
        # or if it starts from block 0. In both cases, we can get the chain wallet address
        # from the parent, or from the sender of block 0

        try:
            chain_address = self.chaindb.get_chain_wallet_address_for_block(block_list[0])
        except ValueError:
            # this means we don't have the correct parent.
            # the procedure is: send head block, if they don't have the parent, they request the missing blocks beyond the local head,
            # and if more than 1, then they come as a chain here. So we must have a block that corresponds to the parent or else this
            # is a conflict block.... we should add the parent to conflict blocks, but we dont know what chain it belongs to...
            return

        i = 1
        for new_block in block_list:
            if i == len(block_list):
                propogate_to_network = True
            else:
                propogate_to_network = False

            success = await self.handle_new_block(new_block, chain_address, propogate_to_network=propogate_to_network)
            if success == False:
                # if one block fails to be imported, no point in importing the rest because they will fail or call this function again
                # creating an infinite loop.
                break

            i += 1

    async def _handle_new_block(self, peer: HLSPeer,
                                msg: Dict[str, Any]) -> None:

        self.logger.debug('received new block from network. processing')
        new_block = msg['block']
        chain_address = msg['chain_address']
        queue_item = NewBlockQueueItem(new_block=new_block, chain_address=chain_address, peer=peer)
        self._new_blocks_to_import.put_nowait(queue_item)

        # await self.handle_new_block(new_block, chain_address, peer = peer)

    async def handle_new_block(self, new_block: P2PBlock, chain_address: bytes, peer: HLSPeer = None,
                               propogate_to_network: bool = True, from_rpc: bool = False) -> Optional[bool]:
        # TODO. Here we need to validate the block as much as we can. Try to do this in a way where we can run it in another process to speed it up.
        # No point in doing anything if the block is invalid.
        # or to speed up transaction throughput we could just rely on the import to validate.
        # if we do that, we just cant re-broadcast the blocks until we have successfully imported. So if the block goes to unprocessed
        # run the validator before sending out. lets make sure everything is validated in chain before saving as unprocessed.

        '''
        This returns true if the block is imported successfully, False otherwise
        If the block comes from RPC, we need to treat it differently. If it is invalid for any reason whatsoever, we just delete.
        '''

        self.logger.debug("handling new block")
        chain = self.node.get_new_chain()
        required_min_gas_price = self.chaindb.get_required_block_min_gas_price(new_block.header.timestamp)
        block_gas_price = int(get_block_average_transaction_gas_price(new_block))

        if block_gas_price < required_min_gas_price:
            self.logger.debug(
                "New block didn't have high enough gas price. block_gas_price = {}, required_min_gas_price = {}".format(
                    block_gas_price, required_min_gas_price))
            return False

        # Get the head of the chain that we have in the database
        # need this to see if we are replacing a block
        replacing_block_permitted = False
        try:
            canonical_head = self.chaindb.get_canonical_head(chain_address)

            # check to see if we are replacing a block
            if new_block.header.block_number <= canonical_head.block_number:
                # it is trying to replace a block that we already have.

                # is it the same as the one we already have?
                local_block_hash = self.chaindb.get_canonical_block_hash(new_block.header.block_number, chain_address)
                if new_block.header.hash == local_block_hash:
                    # we already have this block. Do nothing. Do not propogate if we already have it.
                    self.logger.debug("We already have this block, doing nothing")
                    return True
                else:
                    # check to see if we are expecting this block because it is actually the new consensus block
                    if self._latest_block_conflict_choices_to_change is not None:
                        # we are actually expecting new blocks to overwrite. Lets check to see if this is one of them.
                        block_conflict_choice = BlockConflictChoice(chain_address, new_block.header.block_number,
                                                                    new_block.header.hash)
                        if block_conflict_choice in self._latest_block_conflict_choices_to_change:
                            replacing_block_permitted = True
                            self.logger.debug(
                                "Received a block conflict that we were expecting. going to import and replace ours.")
                    if not replacing_block_permitted:
                        # this is a conflict block. Send it to consensus and let the syncer do its thing.
                        if not from_rpc:
                            self.logger.debug("Received a conflicting block. sending to consensus as block conflict.")
                            self.consensus.add_block_conflict(chain_address, new_block.header.block_number)
                        return False

        except CanonicalHeadNotFound:
            # we have to download the entire chain
            canonical_head = None

        # deal with the possibility of missing blocks
        # it is only possible that we are missing previous blocks if this is not the genesis block
        if new_block.header.block_number > 0:
            if canonical_head is None or new_block.header.block_number > (canonical_head.block_number + 1):
                # we need to download missing blocks.
                # lets keep it simple, just send this same peer a request for the new blocks that we need, plus this one again.

                if peer is not None:
                    if canonical_head is None:
                        block_number_start = 0
                    else:
                        block_number_start = canonical_head.block_number + 1
                    self.logger.debug('asking peer for the rest of missing chian')
                    peer.sub_proto.send_get_chain_segment(chain_address, block_number_start,
                                                          new_block.header.block_number)
                    return False

        if from_rpc:
            # blocks from RPC will be missing fields such as receipts. So they will fail a validation check.
            ensure_block_unchainged = False
        else:
            ensure_block_unchainged = True
        try:
            # if new_block.header.block_number < 200:
            # imported_block = await chain.coro_import_block(new_block,
            #                                    wallet_address = chain_address,
            #                                    allow_replacement = replacing_block_permitted)

            imported_block = chain.import_block(new_block,
                                                wallet_address=chain_address,
                                                allow_replacement=replacing_block_permitted,
                                                ensure_block_unchainged=ensure_block_unchainged)
            # else:
            #     imported_block = chain.import_block_with_profiler(new_block,
            #                                         wallet_address = chain_address,
            #                                         allow_replacement = replacing_block_permitted)

        except ReplacingBlocksNotAllowed:
            self.logger.debug('ReplacingBlocksNotAllowed error. adding to block conflicts')
            if not from_rpc:
                # it has not been validated yet.
                chain.validate_block_specification(new_block)
                self.consensus.add_block_conflict(chain_address, new_block.header.block_number)
            return False
        except ParentNotFound:
            self.logger.debug('ParentNotFound error. adding to block conflicts')
            if not from_rpc:
                # it has not been validated yet

                chain.validate_block_specification(new_block)
                self.consensus.add_block_conflict(chain_address, new_block.header.block_number - 1)
            return False
        except ValidationError as e:
            self.logger.debug('ValidationError error when importing block. Error: {}'.format(e))
            return False
        except ValueError as e:
            self.logger.debug('ValueError error when importing block. Error: {}'.format(e))
            return False
        except Exception as e:
            self.logger.error('tried to import a block and got error {}'.format(e))
            return

        self.logger.debug('successfully imported block')

        if propogate_to_network:
            for loop_peer in self.peer_pool.peers:
                # don't send the block back to the peer who gave it to us.
                if loop_peer != peer:
                    self.logger.debug('sending new block to peer {}'.format(loop_peer))
                    loop_peer.sub_proto.send_new_block(imported_block, chain_address)

        return True


    #
    # Event bus functions
    #
    async def handle_new_block_events(self) -> None:
        async def f() -> None:
            # FIXME: There must be a way to cancel event_bus.stream() when our token is triggered,
            # but for the time being we just wrap everything in self.wait().
            async for req in self.event_bus.stream(NewBlockEvent):
                # We are listening for all `PeerCountRequest` events but we ensure to only send a
                # `PeerCountResponse` to the callsite that made the request.  We do that by
                # retrieving a `BroadcastConfig` from the request via the
                # `event.broadcast_config()` API.
                #self.event_bus.broadcast(PeerCountResponse(len(self)), req.broadcast_config())
                self.logger.debug("Got a new block from the event bus.")
                block = req.block
                chain_address = req.chain_address
                only_propogate_to_network = req.only_propogate_to_network
                if only_propogate_to_network:
                    # in this case, we shouldn't import the block, we just send it to the network
                    # this if for blocks that have already been imported elsewhere but need to be sent to network.
                    self.logger.debug("Sending new block to network")
                    self.propogate_block_to_network(block, chain_address)
                else:
                    self.logger.debug("Adding new block to queue")
                    new_block_queue_item = NewBlockQueueItem(block, chain_address)
                    self._new_blocks_to_import.put_nowait(new_block_queue_item)

        await self.wait(f())


    def propogate_block_to_network(self, block: P2PBlock, chain_address: Address):
        for peer in self.peer_pool.peers:
            self.logger.debug('Sending block {} on chain {} to peer {}'.format(block, encode_hex(chain_address), peer))
            peer.sub_proto.send_new_block(block, chain_address)


class DownloadedBlockPart(NamedTuple):
    part: Union[commands.BlockBody, List[Receipt]]
    unique_key: Union[bytes, Tuple[bytes, bytes]]


class NewBlockQueueItem:
    def __init__(self, new_block: P2PBlock, chain_address: bytes, peer: Union[BasePeer, None] = None,
                 propogate_to_network: bool = True, from_rpc: bool = False):
        self.new_block = new_block
        self.chain_address = chain_address
        self.peer = peer
        self.propogate_to_network = propogate_to_network
        self.from_rpc = from_rpc


# NewBlockQueueItem = namedtuple(NewBlockQueueItem, 'new_block chain_address peer propogate_to_network from_rpc')

def _body_key(header: BlockHeader) -> Tuple[bytes, bytes]:
    """Return the unique key of the body for the given header.

    i.e. a two-tuple with the transaction root and uncles hash.
    """
    return cast(Tuple[bytes, bytes], (header.transaction_root, header.uncles_hash))


def _receipts_key(header: BlockHeader) -> bytes:
    """Return the unique key of the list of receipts for the given header.

    i.e. the header's receipt root.
    """
    return header.receipt_root


def _is_body_empty(header: BlockHeader) -> bool:
    return header.transaction_root == BLANK_ROOT_HASH and header.uncles_hash == EMPTY_UNCLE_HASH


def _is_receipts_empty(header: BlockHeader) -> bool:
    return header.receipt_root == BLANK_ROOT_HASH
