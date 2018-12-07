import asyncio
from asyncio import (
    PriorityQueue,
)

import time
from random import shuffle

from lahja import Endpoint

from helios.exceptions import AlreadyWaiting, NoCandidatePeers
from helios.protocol.common.constants import ROUND_TRIP_TIMEOUT
from helios.protocol.common.exchanges import BaseExchange
from helios.protocol.hls.sync import get_sync_stage_for_block_timestamp
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
    FAST_SYNC_NUM_CHAINS_TO_REQUEST,
    REPLY_TIMEOUT,
    CONSENSUS_SYNC_TIME_PERIOD,
    MOVING_WINDOW_WHERE_HISTORICAL_ROOT_HASH_NOT_SYNCED,
)

from hp2p.exceptions import (
    OperationCancelled,
    DatabaseResyncRequired,
    NotSyncedToAdditiveSyncStartTime, PeerConnectionLost, NoEligiblePeers)
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
    Callable,
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

from helios.utils.sync import (
    prepare_hash_fragments,
    get_missing_hash_locations_list,
)

from helios.nodes.base import Node

from hvm.types import Timestamp

from hvm.db.trie import _make_trie_root_and_nodes

from helios.utils.sync import get_missing_hash_locations_bytes

from helios.protocol.common.datastructures import (
    AdditiveSyncRequestHistory,
    HashFragmentBundle,
    ChainRequestInfo,
    SyncParameters,
    FastSyncParameters,
)

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


# class ChainRequestInfo():
#     def __init__(self, peer, head_root_timestamp, head_root_hash, head_hash_of_last_chain, window_start, window_length,
#                  timestamp_sent):
#         self.peer = peer
#         self.head_root_timestamp = head_root_timestamp
#         self.head_root_hash = head_root_hash
#         self.head_hash_of_last_chain = head_hash_of_last_chain
#         self.window_start = window_start
#         self.window_length = window_length
#         self.timestamp_sent = timestamp_sent



class FastChainSyncer(BaseService, PeerSubscriber):
    """
    Sync with the Ethereum network by fetching/storing block headers, bodies and receipts.

    Here, the run() method will execute the sync loop until our local head is the same as the one
    with the highest TD announced by any of our peers.
    """

    subscription_msg_types: Set[Type[Command]] = {
        commands.GetChains,
        commands.NewBlock,
        commands.GetChronologicalBlockWindow,
        commands.ChronologicalBlockWindow,
        commands.GetChainSegment,
        commands.GetBlocks,
        commands.GetHashFragments,
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
    consensus: Consensus


    def __init__(self,
                 context: ChainContext,
                 peer_pool: HLSPeerPool,
                 consensus: Consensus,
                 node,
                 event_bus: Endpoint = None,
                 token: CancelToken = None) -> None:
        super().__init__(token)
        self.node: Node = node
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

                    self.last_window_length = FAST_SYNC_NUM_CHAINS_TO_REQUEST
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

        if isinstance(cmd, commands.GetChains):
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

                chain_address = await self.chaindb.coro_get_chain_wallet_address_for_block_hash(head_hash)
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
    importing_blocks_lock = asyncio.Lock()
    num_blocks_to_request_at_once = 10000
    _max_fast_sync_workers = 5

    # This is the current index in the list of chains that we require. This may not correspond to the index of the chain.
    # For example, if we need the chains: [0,4,6,76,192], then when _fast_sync_required_chain_list_idx = 2 corresponds to chain 6.
    _fast_sync_required_chain_list_idx = 0
    _fast_sync_use_shared_vars = asyncio.Lock()
    _fast_sync_num_chains_to_request = FAST_SYNC_NUM_CHAINS_TO_REQUEST


    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._initial_sync_complete = asyncio.Event()
        # [(new_chronological_blocks, final_root_hash),...]
        self._new_chronological_block_window = asyncio.Queue()

        self.chain_head_db.load_saved_root_hash()

    async def _run(self) -> None:

        self.logger.debug("Starting regular chainsyncer. Waiting for consensus and chain config to initialize.")
        self.run_daemon_task(self._handle_msg_loop())
        consensus_ready = await self.consensus.coro_is_ready.wait()
        if consensus_ready:
            self.logger.debug('waiting for consensus min gas system ready')
            min_gas_system_ready = await self.consensus.coro_min_gas_system_ready.wait()
            if min_gas_system_ready:
                self.logger.debug("consensus ready")
                with self.subscribe(self.peer_pool):

                    self.run_daemon_task(self._handle_import_block_loop())
                    if self.event_bus is not None:
                        self.run_daemon_task(self.handle_new_block_events())

                    # this runs forever
                    self.run_daemon_task(self.sync_with_consensus_loop())
                    #self.run_daemon_task(self.fast_sync_main())

                    await self.wait(self.sync_block_conflict_with_consensus_loop(), self.cancel_token)



    #
    # Helper functions for syncing
    #
    async def handle_getting_request_from_peers(self,
                                                request_function_name: str,
                                                request_function_parameters: Dict[str, Any],
                                                peer: HLSPeer,
                                                additional_candidate_peers: List[HLSPeer] = [],
                                                num_attempts_when_no_additional_peers: int = 0) -> Tuple[Any, HLSPeer]:
        '''
        Cycles through peers trying to get the specified request. If it runs out of peers it will raise NoCandidatePeers().
        It returns the result and the peer who returned it. It also pops peers out of additional_candidate_peers as they are
        used up or fail.
        :param timestamp:
        :param peer:
        :param additional_candidate_peers:
        :return:
        '''
        num_retries = 0
        while True:
            try:
                result = await getattr(peer.requests, request_function_name)(**request_function_parameters)
            except AlreadyWaiting:
                # put this peer at the beginning of the list and pop the next peer from the end to try with
                additional_candidate_peers.insert(0, peer)
                peer = additional_candidate_peers.pop()
                if len(additional_candidate_peers) == 0:
                    # we are just retrying the same peer. Lets wait some time so we don't get stuck in a loop waiting for them
                    self.logger.debug("We only have 1 candidate peer for the {} request and we are already waiting. Will wait and re-request soon.".format(request_function_name))
                    await asyncio.sleep(ROUND_TRIP_TIMEOUT/2)
            except Exception as e:
                try:
                    peer = additional_candidate_peers.pop()
                except IndexError:
                    if num_retries < num_attempts_when_no_additional_peers:
                        num_retries += 1
                        continue
                    else:
                        self.logger.debug("Couldn't find any peers that responded to the {} request.".format(request_function_name))
                        raise NoCandidatePeers()
            else:
                break

        return result, peer


    async def request_blocks_then_priority_import(self, block_hash_list: List[Hash32], peer: HLSPeer, additional_candidate_peers: List[HLSPeer], force_replace_existing_blocks = True) -> HLSPeer:
        '''
        Requests the blocks from peer in manageable chunks. If peer doesn't respond it cycles through additional_candidate_peers.
        It then imports the blocks to our chain.
        If it runs out of peers to request from then it raises NoCandidatePeers()
        This also assumes that we want these new blocks, so by default we replace any existing blocks that they might conflict with.
        :param block_hash_list:
        :param peer:
        :param additional_candidate_peers:
        :return:
        '''
        self.logger.debug("request_blocks_then_priority_import")

        for i in range(0, len(block_hash_list), self.num_blocks_to_request_at_once):
            current_request_hashes = block_hash_list[i: i + self.num_blocks_to_request_at_once]

            received_blocks, peer = await self.handle_getting_request_from_peers(request_function_name="get_blocks",
                                                                         request_function_parameters={'block_hashes': tuple(current_request_hashes)},
                                                                         peer=peer,
                                                                         additional_candidate_peers=additional_candidate_peers)
            received_blocks = cast(List[P2PBlock], received_blocks)

            async with self.importing_blocks_lock:
                for block in received_blocks:
                    await self.handle_new_block(new_block=block,
                                                peer=peer,
                                                propogate_to_network=False,
                                                from_rpc=False,
                                                force_replace_existing_blocks = force_replace_existing_blocks)

        return peer

    async def remove_block_by_hash(self, block_hash: Hash32) -> None:
        async with self.importing_blocks_lock:
            chain = self.node.get_new_chain()
            try:
                await chain.coro_purge_block_and_all_children_and_set_parent_as_chain_head_by_hash(block_hash)
            except Exception:
                pass

    #
    # Loops
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
                async with self.importing_blocks_lock:
                    await self.handle_new_block(new_block=new_block_queue_item.new_block,
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

    async def sync_with_consensus_loop(self):
        '''
        It is the duty of nodes who are not in consensus to figure out what differences their database has, and bringing their database in line with consensus.
        If one of these nodes is missing blocks, it will request them from one of the nodes in consensus. If one of these nodes has
        new blocks that the consensus nodes do not have, it should send the new blocks to them.

        If we need new blocks, lets request them all from one peer.

        If we have blocks that they need, send them out to all peers who need it.
        :return:
        '''

        # We have 3 stages of syncing. The window that is still active, and still filling up with new blocks,
        # gets synced as much as possible by nodes sending out new blocks to all other nodes.
        # We cant effeciently sync this window with the hash fragment method because it will be continuously
        # changing.
        #
        # The second stage of syncing, from about 1000 seconds ago until 2000 or 3000 seconds ago
        # is where we look at differences in blockchain databases between the nodes
        # and add any blocks that other nodes have that we don't. We also inform other nodes if we have blocks
        # that they are missing.
        #
        # If we arent synced by then, we perform a third stage of syncing, which is where we take the blockchain database
        # that is currently in consensus. This differs from the second stage because we don't add any blocks
        # that are missing. We simply go with whatever database currently has the most stake and is in consensus.
        #
        # These stages are labeled from top to bottom 4, 3, 2. stage 1 is fast sync. Stage 0 is unknown.

        # TODO: track the block requests we send to peers. Then make sure we don't keep sending the same requests to
        # a peer that isn't responding.
        self.logger.debug("additively_sync_recent_blocks_with_consensus starting")

        while self.is_operational:
            await self.sync_with_consensus()
            await asyncio.sleep(CONSENSUS_SYNC_TIME_PERIOD)

    async def sync_block_conflict_with_consensus_loop(self):
        self.logger.debug("sync_block_conflict_with_consensus_loop starting")
        while self.is_operational:
            await self.sync_block_conflict_with_consensus()
            await asyncio.sleep(CONSENSUS_SYNC_TIME_PERIOD)

    #
    # Core functionality. Methods for performing sync
    #
    async def sync_with_consensus(self):
        try:
            sync_parameters = await self.consensus.get_blockchain_sync_parameters()
        except NoEligiblePeers:
            self.logger.debug("No peers have the data we need to sync with. Skipping sync loop.")

        else:
            fragment_length = 3
            if sync_parameters is None:
                self.logger.debug("We are fully synced. Skipping sync loop and pausing before checking again.")
                return

            #TODO:REMOVE THIS IS FOR TESTING
            sync_parameters.sync_stage = 1

            sync_stage = sync_parameters.sync_stage
            if sync_stage >= 4:
                self.logger.debug("We are synced up to stage 4. Skipping sync loop and pausing before checking again.")
                return

            if sync_stage == 1:
                # TODO: perform fast sync now. await the fast sync before continuing.
                # fast sync should first check our chain head fragments to resume any previously
                # attempted fast sync.
                await self.fast_sync_main(sync_parameters)
                return

            additional_candidate_peers = list(sync_parameters.peers_to_sync_with)
            peer_to_sync_with = additional_candidate_peers.pop()
            chronological_window_timestamp = sync_parameters.timestamp_for_chronoligcal_block_window

            #TODO: NEED TO CONFIRM THAT THESE BLOCKS ACTUALLY BRING US TO THE CORRECT ROOT HASH
            timestamp_block_hashes = await self.chain_head_db.coro_load_chronological_block_window(chronological_window_timestamp)
            if timestamp_block_hashes is None:
                # we have no blocks for this window. So just request all of them automatically.
                # This is the same for all versions of syncing
                self.logger.debug("We have no blocks for this chronological block window. Requesting all blocks to add to our database.")
                try:
                    fragment_bundle, peer_to_sync_with = await self.handle_getting_request_from_peers(request_function_name = "get_hash_fragments",
                                                                                                 request_function_parameters = {'timestamp': chronological_window_timestamp},
                                                                                                 peer = peer_to_sync_with,
                                                                                                 additional_candidate_peers = additional_candidate_peers)
                    fragment_bundle = cast(HashFragmentBundle, fragment_bundle)

                    required_block_hashes = cast(List[Hash32], fragment_bundle.fragments)

                    peer_to_sync_with = await self.request_blocks_then_priority_import(block_hash_list = required_block_hashes,
                                                                                         peer = peer_to_sync_with,
                                                                                         additional_candidate_peers = additional_candidate_peers)
                except NoCandidatePeers:
                    return

            else:
                our_block_hashes = [x[1] for x in timestamp_block_hashes]
                our_fragment_list = prepare_hash_fragments(our_block_hashes, fragment_length)

                try:
                    while True:
                        their_fragment_bundle, peer_to_sync_with = await self.handle_getting_request_from_peers(request_function_name = "get_hash_fragments",
                                                                                                         request_function_parameters = {'timestamp': chronological_window_timestamp,
                                                                                                                                        'fragment_length':fragment_length},
                                                                                                         peer = peer_to_sync_with,
                                                                                                         additional_candidate_peers = additional_candidate_peers)
                        their_fragment_bundle = cast(HashFragmentBundle, their_fragment_bundle)
                        their_fragment_list = their_fragment_bundle.fragments

                        hash_positions_of_theirs_that_we_need, hash_positions_of_ours_that_they_need = get_missing_hash_locations_list(
                                                                                                        our_hash_fragments=our_fragment_list,
                                                                                                        their_hash_fragments=their_fragment_list,
                                                                                                        )

                        diff_verification_block_hashes = list(our_block_hashes)
                        if len(hash_positions_of_ours_that_they_need) > 0:
                            for idx in sorted(hash_positions_of_ours_that_they_need, key= lambda x: -x):
                                del(diff_verification_block_hashes[idx])

                        # now lets request the missing hashes from them, then verify that adding them to our hashes results in the correct root hash
                        # We must get these hashes from the same peer. If they don't respond here then we need to start over again.
                        if len(hash_positions_of_theirs_that_we_need) > 0:
                            their_fragment_bundle_we_need_to_add, peer_to_sync_with = await self.handle_getting_request_from_peers(
                                                                                                     request_function_name = "get_hash_fragments",
                                                                                                     request_function_parameters = {'timestamp': chronological_window_timestamp,
                                                                                                                                    'only_these_indices':list(hash_positions_of_theirs_that_we_need)},
                                                                                                     peer = peer_to_sync_with,
                                                                                                     num_attempts_when_no_additional_peers = 3)

                            their_fragment_bundle_we_need_to_add = cast(HashFragmentBundle, their_fragment_bundle_we_need_to_add)
                            their_fragment_list_we_need_to_add = their_fragment_bundle_we_need_to_add.fragments
                            diff_verification_block_hashes.extend(their_fragment_list_we_need_to_add)

                        diff_verification_root_hash, _ = _make_trie_root_and_nodes(tuple(diff_verification_block_hashes))

                        if diff_verification_root_hash == their_fragment_bundle.root_hash_of_the_full_hashes:
                            self.logger.debug("Diff was correct. Syncing blocks now.")

                            if len(hash_positions_of_theirs_that_we_need) > 0:
                                required_block_hashes = cast(List[Hash32], their_fragment_list_we_need_to_add)

                                peer_to_sync_with = await self.request_blocks_then_priority_import(block_hash_list = required_block_hashes,
                                                                                                   peer = peer_to_sync_with,
                                                                                                   additional_candidate_peers = additional_candidate_peers)


                            if len(hash_positions_of_ours_that_they_need) > 0:
                                for idx in hash_positions_of_ours_that_they_need:
                                    #send these to all peers
                                    block_hash = our_block_hashes[idx]
                                    if sync_stage <= 2:
                                        # We need to delete any blocks that they do not have, this will bring us in line with consensus.
                                        await self.remove_block_by_hash(block_hash)
                                    else:
                                        # At this stage of syncing, we should send them the blocks they don't have so they can add them too.
                                        for peer in sync_parameters.peers_to_sync_with:
                                            try:
                                                block = await self.chaindb.coro_get_block_by_hash(block_hash, self.chain.get_vm().get_block_class())
                                                peer.sub_proto.send_new_block(block)
                                            except Exception:
                                                pass

                            self.logger.debug("Successfully synced")
                            break


                        if fragment_length > 16:
                            self.logger.warning("Diff verification failed even with max fragment length. This is very unlikely to occur and something has probably gone wrong.")
                            break
                        self.logger.debug("Diff was incorrect, increasing fragment length and trying again.")
                        fragment_length += 1
                except NoCandidatePeers:
                    return

    # If the node crashes during fast sync, we don't need to resume fast sync at the exact same root hash timestamp.
    # This is because the vast majority of chains will be unchanged since the last timestamp. So we can just start
    # a new sync with the timestamp of 24 or 48 hours ago, and the diff will tell us which chains have changed so that
    # we can request them.
    #
    #
    #
    async def fast_sync_main(self, sync_parameters: SyncParameters):
        self.logger.debug('fast_sync_main starting')
        self._fast_sync_required_chain_list_idx = 0

        fragment_length = 3
        additional_candidate_peers = list(sync_parameters.peers_to_sync_with)
        peer_to_sync_with = additional_candidate_peers.pop()
        chronological_window_timestamp = sync_parameters.timestamp_for_chronoligcal_block_window
        consensus_root_hash = sync_parameters.consensus_root_hash

        # before starting workers, lets figure out which chains we already have.
        # We can make a shared list of chains that the workers can skip
        # Since we are syncing to a specific timestamp, if any of the nodes somehow add a new block that is older than this timestamp,
        # then the indices here will become out of sync. We can check to see if the indices/chains are out of sync by comparing the
        # chains that we are given with the expected fragments. If they don't match, go to the next peer. If no peers match, quit this
        # fast sync and allow the syncer to restart the whole fast sync process. This will resume where we left off.
        self.chain_head_db.load_saved_root_hash()
        our_block_hashes = list(await self.chain_head_db.coro_get_head_block_hashes_list())

        while self.is_operational:
            our_fragment_list = prepare_hash_fragments(our_block_hashes, fragment_length)

            try:
                their_fragment_bundle, peer_to_sync_with = await self.handle_getting_request_from_peers(request_function_name = "get_hash_fragments",
                                                                                                         request_function_parameters = {'timestamp': chronological_window_timestamp,
                                                                                                                                        'fragment_length':fragment_length,
                                                                                                                                        'hash_type_id': 2},
                                                                                                         peer = peer_to_sync_with,
                                                                                                         additional_candidate_peers = additional_candidate_peers)
            except NoCandidatePeers:
                return

            their_fragment_bundle = cast(HashFragmentBundle, their_fragment_bundle)
            their_fragment_list = their_fragment_bundle.fragments

            hash_positions_of_theirs_that_we_need, hash_positions_of_ours_that_they_need = get_missing_hash_locations_list(
                                                                                            our_hash_fragments=our_fragment_list,
                                                                                            their_hash_fragments=their_fragment_list,
                                                                                            )

            if len(our_fragment_list) > len(their_fragment_list) and len(their_fragment_list) > 0:
                if len(hash_positions_of_ours_that_they_need) > 0:
                    self.logger.debug("Fast sync: deleting extra chains we have that arent in the consensus db.")
                    for idx in hash_positions_of_ours_that_they_need:
                        chain_head_hash = our_block_hashes[idx]
                        chain_block_hashes = await self.chaindb.coro_get_all_block_hashes_on_chain_by_head_block_hash(chain_head_hash)

                        # by removing the genesis block on the chain, the vm will remove all children blocks automatically.
                        await self.remove_block_by_hash(chain_block_hashes[0])


            fast_sync_parameters = FastSyncParameters(their_fragment_list, list(hash_positions_of_theirs_that_we_need))

            worker_tasks = []
            num_workers = min(self._max_fast_sync_workers, len(sync_parameters.peers_to_sync_with))
            for i in range(num_workers):
                worker_tasks.append(self.run_task(self.fast_sync_worker(sync_parameters, fast_sync_parameters)))

            await self.wait_all(worker_tasks)

            resulting_chain_head_root_hash = self.chain_head_db.get_saved_root_hash()
            if resulting_chain_head_root_hash == consensus_root_hash:
                break

            fragment_length += 1
            if fragment_length >= 16:
                self.logger.debug("Fast sync checked up to max fragment length and our db still incorrect.")
                break



        self.logger.debug('fast_sync_main finished')

        # at this point, we should check our root hash. If it is unexpected, then increase the fragment length and redo the sync within this loop.
        # Do a max of 16 or something

    async def fast_sync_worker(self, sync_parameters: SyncParameters, fast_sync_parameters: FastSyncParameters):
        self.logger.debug("fast_sync_worker started")

        expected_fragment_list = fast_sync_parameters.expected_block_hash_fragments
        chains_that_we_need = fast_sync_parameters.chain_idx_that_we_need
        timestamp = sync_parameters.timestamp_for_root_hash
        additional_candidate_peers = list(sync_parameters.peers_to_sync_with)
        peer_to_sync_with = additional_candidate_peers.pop()
        num_chains_to_request = len(chains_that_we_need)

        while self.is_operational:
            async with self._fast_sync_use_shared_vars:
                start = self._fast_sync_required_chain_list_idx
                end = start + self._fast_sync_num_chains_to_request
                self._fast_sync_required_chain_list_idx = end
            self.logger.debug("Requesting chains from {} to {}".format(start, end))

            if start >= num_chains_to_request:
                #we have requested all of the chains already
                break

            idx_list = chains_that_we_need[start:end]
            expected_chain_head_hash_fragments = []
            for idx in idx_list:
                expected_chain_head_hash_fragments.append(expected_fragment_list[idx])

            chains, peer_to_sync_with = await self.handle_getting_request_from_peers(request_function_name = "send_get_chains",
                                                                                                     request_function_parameters = {'timestamp': timestamp,
                                                                                                                                    'idx_list':idx_list,
                                                                                                                                    'expected_chain_head_hash_fragments': expected_chain_head_hash_fragments},
                                                                                                     peer = peer_to_sync_with,
                                                                                                     additional_candidate_peers = additional_candidate_peers)
            async with self.importing_blocks_lock:
                for chain in chains:
                    await self.chain.coro_import_chain(block_list=chain, save_block_head_hash_timestamp=False)


        self.logger.debug("Worker finished getting all required chains for fast sync.")
        #raise OperationCancelled when finished to exit cleanly.
        raise OperationCancelled()



    async def sync_block_conflict_with_consensus(self):
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



    #
    # Peer communication handlers
    #
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
        elif isinstance(cmd, commands.GetChains):
            await self._handle_get_chains(peer, cast(Dict[str, Any], msg))
        elif isinstance(cmd, commands.GetBlocks):
            await self._handle_get_blocks(peer, cast(Iterable, msg))
        elif isinstance(cmd, commands.GetHashFragments):
            await self._handle_get_hash_fragments(peer, cast(Dict[str, Any], msg))



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

        peer.sub_proto.send_blocks(chain_segment)

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

    async def _handle_get_chains(self,
                            peer: HLSPeer,
                            msg: Dict[str, Any]) -> None:
        self.logger.debug("received get_chains request")
        timestamp = msg['timestamp']
        idx_list = msg['idx_list']

        root_hash = await self.chain_head_db.coro_get_historical_root_hash(timestamp)

        chain_head_hashes = await self.chain_head_db.coro_get_head_block_hashes_by_idx_list(idx_list, root_hash)

        chains = []
        for head_hash in chain_head_hashes:
            chain = await self.chaindb.coro_get_all_blocks_on_chain_by_head_block_hash(head_hash, self.chain.get_vm().get_block_class())
            chains.append(chain)

        peer.sub_proto.send_chains(chains)



    async def _handle_new_block(self, peer: HLSPeer,
                                msg: Dict[str, Any]) -> None:

        self.logger.debug('received new block from network. processing')
        new_block = msg['block']

        queue_item = NewBlockQueueItem(new_block=new_block, peer=peer)
        self._new_blocks_to_import.put_nowait(queue_item)

        # await self.handle_new_block(new_block, chain_address, peer = peer)

    async def handle_new_block(self, new_block: P2PBlock, peer: HLSPeer = None,
                               propogate_to_network: bool = True, from_rpc: bool = False,
                               force_replace_existing_blocks = False) -> Optional[bool]:
        # TODO. Here we need to validate the block as much as we can. Try to do this in a way where we can run it in another process to speed it up.
        # No point in doing anything if the block is invalid.
        # or to speed up transaction throughput we could just rely on the import to validate.
        # if we do that, we just cant re-broadcast the blocks until we have successfully imported. So if the block goes to unprocessed
        # run the validator before sending out. lets make sure everything is validated in chain before saving as unprocessed.

        '''
        This returns true if the block is imported successfully, False otherwise
        If the block comes from RPC, we need to treat it differently. If it is invalid for any reason whatsoever, we just delete.
        '''
        chain_address = new_block.header.chain_address

        self.logger.debug("handling new block")
        chain = self.node.get_new_chain()

        #we only check the min gas requirements for sync stage 3, 4
        if get_sync_stage_for_block_timestamp(new_block.header.timestamp) > 2 and len(new_block.transactions) != 0:
            required_min_gas_price = self.chaindb.get_required_block_min_gas_price(new_block.header.timestamp)
            block_gas_price = int(get_block_average_transaction_gas_price(new_block))

            if block_gas_price < required_min_gas_price:
                self.logger.debug(
                    "New block didn't have high enough gas price. block_gas_price = {}, required_min_gas_price = {}".format(
                        block_gas_price, required_min_gas_price))
                return False

        else:
            pass

        # Get the head of the chain that we have in the database
        # need this to see if we are replacing a block
        replacing_block_permitted = force_replace_existing_blocks
        resolving_block_conflict = False
        try:
            canonical_head = self.chaindb.get_canonical_head(chain_address)
            if not replacing_block_permitted:
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
                            new_block_conflict_choice = BlockConflictChoice(chain_address, new_block.header.block_number,
                                                                        new_block.header.hash)
                            if new_block_conflict_choice in self._latest_block_conflict_choices_to_change:
                                replacing_block_permitted = True
                                resolving_block_conflict = True
                                self.logger.debug(
                                    "Received a block conflict that we were expecting. going to import and replace ours.")

                        if not replacing_block_permitted:
                            # this is a conflict block. Send it to consensus and let the syncer do its thing.
                            if not from_rpc:
                                if not self.consensus.has_block_conflict(chain_address, new_block.header.block_number):
                                    self.logger.debug("Received a conflicting block. sending to consensus as block conflict. Also sending our conflict block back to the peer.")
                                    self.consensus.add_block_conflict(chain_address, new_block.header.block_number)

                                    #lets also send this peer our conflict block to let it know that it exists.
                                    conflict_block = self.chaindb.get_block_by_number(block_number = new_block.header.block_number,
                                                                                      wallet_address = new_block.header.chain_address,
                                                                                      block_class = chain.get_vm().get_block_class())
                                    peer.sub_proto.send_new_block(cast(P2PBlock, conflict_block))

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
            return False

        self.logger.debug('successfully imported block')

        #if we replaced our own block because it was a block conflict, then we need to remove the entry from consensus now
        if resolving_block_conflict:
            self.logger.debug("Succesfully replaced our block with consensus block. Deleting conflict block lookup.")
            self.consensus.remove_block_conflict(chain_wallet_address = imported_block.header.chain_address,
                                                 block_number = imported_block.header.block_number)
            try:
                self._latest_block_conflict_choices_to_change.remove(new_block_conflict_choice)
            except KeyError:
                pass


        if propogate_to_network:
            for loop_peer in self.peer_pool.peers:
                # don't send the block back to the peer who gave it to us.
                if loop_peer != peer:
                    self.logger.debug('sending new block to peer {}'.format(loop_peer))
                    loop_peer.sub_proto.send_new_block(imported_block)

        return True


    async def _handle_get_hash_fragments(self, peer: HLSPeer, msg) -> None:
        self.logger.debug("Received request to send chronological block hash fragments.")

        timestamp = msg['timestamp']
        fragment_length = msg['fragment_length']
        hash_type_id = msg['hash_type_id']

        if hash_type_id == 1:
            if msg['entire_window']:
                timestamp_block_hashes = await self.chain_head_db.coro_load_chronological_block_window(timestamp)

                if timestamp_block_hashes is None:
                        peer.sub_proto.send_hash_fragments(fragments = [],
                                                           timestamp = timestamp,
                                                           fragment_length = fragment_length,
                                                           root_hash_of_just_this_chronological_block_window=BLANK_ROOT_HASH,
                                                           hash_type_id=hash_type_id)

                else:
                    block_hashes = [x[1] for x in timestamp_block_hashes]
                    fragment_list = prepare_hash_fragments(block_hashes, fragment_length)
                    trie_root, _ = _make_trie_root_and_nodes(tuple(block_hashes))
                    peer.sub_proto.send_hash_fragments(fragments=fragment_list,
                                                       timestamp=timestamp,
                                                       fragment_length=fragment_length,
                                                       root_hash_of_just_this_chronological_block_window=cast(Hash32, trie_root),
                                                       hash_type_id=hash_type_id)

                    # we also have to save the info in the peer so that we know what they are talking about later when they reply asking for hashes
                    peer.additive_sync_request_history = AdditiveSyncRequestHistory(chronological_window_timestamp = timestamp,
                                                                                    fragment_length = fragment_length,
                                                                                    root_hash_of_just_this_chronological_block_window = cast(Hash32, trie_root),
                                                                                    local_hashes_sent_to_peer = block_hashes)
            else:
                #if they are requesting hashes of specified indices, then they are referring to the hashes we already sent them.
                if peer.additive_sync_request_history is None:
                    self.logger.error("Peer asked for hash fragments relative to the list we sent, but the peer object doesn't contain any history.")
                    peer.sub_proto.send_hash_fragments(fragments=[],
                                                       timestamp=timestamp,
                                                       fragment_length=fragment_length,
                                                       root_hash_of_just_this_chronological_block_window=BLANK_ROOT_HASH,
                                                       hash_type_id=hash_type_id)
                else:
                    self.logger.debug("Sending peer hash fragments relative to the list we sent earlier.")
                    hashes_to_send = []
                    for index in msg['only_these_indices']:
                        hashes_to_send.append(peer.additive_sync_request_history.local_hashes_sent_to_peer[index])

                    fragment_list = prepare_hash_fragments(hashes_to_send, fragment_length)
                    peer.sub_proto.send_hash_fragments(fragments=fragment_list,
                                                       timestamp=timestamp,
                                                       fragment_length=fragment_length,
                                                       root_hash_of_just_this_chronological_block_window=peer.additive_sync_request_history.root_hash_of_just_this_chronological_block_window,
                                                       hash_type_id=hash_type_id)





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
                only_propogate_to_network = req.only_propogate_to_network
                if only_propogate_to_network:
                    # in this case, we shouldn't import the block, we just send it to the network
                    # this if for blocks that have already been imported elsewhere but need to be sent to network.
                    self.logger.debug("Sending new block to network")
                    self.propogate_block_to_network(block)
                else:
                    self.logger.debug("Adding new block to queue")
                    new_block_queue_item = NewBlockQueueItem(block)
                    self._new_blocks_to_import.put_nowait(new_block_queue_item)

        await self.wait(f())


    def propogate_block_to_network(self, block: P2PBlock):
        for peer in self.peer_pool.peers:
            self.logger.debug('Sending block {} on chain {} to peer {}'.format(block, encode_hex(block.header.chain_address), peer))
            peer.sub_proto.send_new_block(block)


class DownloadedBlockPart(NamedTuple):
    part: Union[commands.BlockBody, List[Receipt]]
    unique_key: Union[bytes, Tuple[bytes, bytes]]


class NewBlockQueueItem:
    def __init__(self, new_block: P2PBlock, peer: Union[BasePeer, None] = None,
                 propogate_to_network: bool = True, from_rpc: bool = False):
        self.new_block = new_block
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


