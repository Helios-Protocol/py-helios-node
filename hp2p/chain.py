import asyncio
import logging
import math
import operator
import time
from collections import namedtuple
from random import shuffle
from typing import (
    Any,
    Callable,
    Dict,
    List,
    NamedTuple,
    Tuple,
    Union,
    cast,
    Iterable)

from cytoolz import (
    partition_all,
    unique,
)

from eth_typing import BlockNumber, Hash32
from eth_utils import (
    encode_hex,
)

from hvm.utils.blocks import get_block_average_transaction_gas_price

from hvm.constants import (
    BLANK_ROOT_HASH, 
    EMPTY_UNCLE_HASH, 
    GENESIS_PARENT_HASH,
    NUMBER_OF_HEAD_HASH_TO_SAVE,
    TIME_BETWEEN_HEAD_HASH_SAVE,
    ZERO_HASH32,
)
from hvm.chains import AsyncChain
from hvm.db.chain import AsyncChainDB
from hvm.db.trie import make_trie_root_and_nodes
from hvm.exceptions import (
    HeaderNotFound, 
    SyncerOutOfOrder,
    LocalRootHashNotAsExpected,
    CanonicalHeadNotFound,
    ReplacingBlocksNotAllowed,
    ParentNotFound,
    ValidationError,
)
from hvm.rlp.headers import BlockHeader
from hvm.rlp.receipts import Receipt
from hvm.rlp.transactions import BaseTransaction

from hp2p.constants import (
    FAST_SYNC_CUTOFF_PERIOD,
    NUM_CHAINS_TO_REQUEST,
    REPLY_TIMEOUT,
    CONSENSUS_SYNC_TIME_PERIOD,
    MOVING_WINDOW_WHERE_HISTORICAL_ROOT_HASH_NOT_SYNCED,
)

from hp2p import protocol
from hp2p import eth
from hp2p import hls
from hp2p.cancel_token import CancelToken
from hp2p.exceptions import (
    NoEligiblePeers, 
    OperationCancelled,
    DatabaseResyncRequired,
)
from hp2p.peer import BasePeer, HLSPeer, PeerPool, PeerPoolSubscriber
from hp2p.rlp import (
    BlockBody, 
    P2PTransaction, 
    P2PBlock
)
from hp2p.service import BaseService
from hp2p.utils import (
    get_process_pool_executor,
)

from sortedcontainers import (
    SortedDict,
    SortedList
)
from helios.utils.profiling import (
    setup_cprofiler,
)


from hp2p.consensus import BlockConflictChoice

#next chain head hash is for the case where we are re-syncing and have a bunch of chains already.
#dont need to re-download the whole chain if we already have part of it. We might also be missing some chains,
#so sending the next head hash allows the other node to tell if we are missing a chain
#window start of 0 means just get the next window_length of blockchains.
class ChainRequestInfo():
    def __init__(self, peer, head_root_timestamp, head_root_hash, head_hash_of_last_chain, window_start, window_length, timestamp_sent):
        self.peer = peer
        self.head_root_timestamp = head_root_timestamp
        self.head_root_hash = head_root_hash
        self.head_hash_of_last_chain = head_hash_of_last_chain
        self.window_start = window_start
        self.window_length = window_length
        self.timestamp_sent = timestamp_sent
        
class FastChainSyncer(BaseService, PeerPoolSubscriber):
    """
    Sync with the Ethereum network by fetching/storing block headers, bodies and receipts.

    Here, the run() method will execute the sync loop until our local head is the same as the one
    with the highest TD announced by any of our peers.
    """
    logger = logging.getLogger("hp2p.chain.ChainSyncer")
    
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

    def __init__(self,
                 chain,
                 chaindb: AsyncChainDB,
                 chain_head_db,
                 base_db,
                 peer_pool: PeerPool,
                 consensus,
                 node,
                 token: CancelToken = None) -> None:
        super().__init__(token)
        self.node = node
        self.consensus = consensus
        self.chain = chain
        self.chaindb = chaindb
        self.chain_head_db = chain_head_db
        self.base_db = base_db
        self.peer_pool = peer_pool
        self._syncing = False
        self._sync_complete = asyncio.Event()
        self._sync_requests: asyncio.Queue[HLSPeer] = asyncio.Queue()
        self._idle_peers: asyncio.Queue[HLSPeer] = asyncio.Queue()
        self._idle_peers_in_consensus: asyncio.Queue[HLSPeer] = asyncio.Queue()
        self._new_headers: asyncio.Queue[List[BlockHeader]] = asyncio.Queue()
        self._new_blocks_to_import: asyncio.Queue[List[NewBlockQueueItem]] = asyncio.Queue()
        self.rpc_queue: asyncio.Queue[HLSPeer] = asyncio.Queue()
        # Those are used by our msg handlers and _download_block_parts() in order to track missing
        # bodies/receipts for a given chain segment.
        self._downloaded_receipts: asyncio.Queue[Tuple[HLSPeer, List[DownloadedBlockPart]]] = asyncio.Queue()  # noqa: E501
        self._downloaded_bodies: asyncio.Queue[Tuple[HLSPeer, List[DownloadedBlockPart]]] = asyncio.Queue()  # noqa: E501
        self._executor = get_process_pool_executor()
        
        #[{peer_wallet_address: ChainRequestInfo},{peer_wallet_address: ChainRequestInfo}...]
        self.pending_chain_requests = {}
        self.failed_chain_requests = {}
        
        #[{peer_wallet_address: num_chains_received},{peer_wallet_address: num_chains_received}...]
        self.num_chains_returned_in_incomplete_requests = {}
        
        
        #number of chains ahead of the last chain we requested. Inclusive
        self.chain_request_num_ahead = 0
        
        self.syncer_initialized = asyncio.Event()
        self.received_final_chain = asyncio.Event()
        
        self.writing_chain_request_vars = asyncio.Lock()
        
        self.logger.debug('this node wallet address = {}'.format(self.consensus.chain_config.node_wallet_address))
        
    def register_peer(self, peer: BasePeer) -> None:
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
                if(peer_root_hash_timestamps[timestamp_to_check] == root_hash_to_check):
                    self._idle_peers_in_consensus.put_nowait(peer)
                    self.logger.debug("Added peer {} to consensus queue2".format(peer.wallet_address))
                else:
                    self._idle_peers.put_nowait(peer)
                    self.logger.debug("Added peer {} to non-consensus queue3".format(peer.wallet_address))
                    self.logger.debug("our timestamp and root hash: {} {}".format(timestamp_to_check, root_hash_to_check))
                    self.logger.debug("their  root hash: {}".format(peer_root_hash_timestamps[timestamp_to_check]))
            except KeyError:
                #ours may be newer than theirs, but still matching. check their latest one and see if it matches
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
        #empty the two queues
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
          
        #then requeue them all again
        for peer in peers :
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
        asyncio.ensure_future(self._handle_msg_loop())
        consensus_ready = await self.consensus.coro_is_ready.wait()
        if consensus_ready:
            self.logger.debug("consensus ready")
            sync_parameters_ready = await self.initialize_sync_parameters()
            if sync_parameters_ready:
                self.logger.debug("Syncing parameters set")
                with self.subscribe(self.peer_pool):
                    asyncio.ensure_future(self.re_queue_timeout_peers())
                    while True:
                        await self.wait_first(self.send_chain_requests(), self._sync_complete.wait())
                        #await self.send_chain_requests()
                        
                        if self._sync_complete.is_set():
                            self.finalize_complete_fast_sync()
                            self.logger.info("fast sync complete")
                            return
                        
    def finalize_complete_fast_sync(self):
        self.chain_head_db.initialize_historical_root_hashes(self.current_syncing_root_hash, self.current_syncing_timestamp)
        


    #step 1) determine which root hash to sync too
    #step 2) connect to peers that have that root hash
    async def initialize_sync_parameters(self):
        while not self.syncer_initialized.is_set():
            if self.current_syncing_root_timestamp != None:
                if self.current_syncing_root_timestamp < int(time.time()) - NUMBER_OF_HEAD_HASH_TO_SAVE*TIME_BETWEEN_HEAD_HASH_SAVE:
                    #it is too old, we have to choose a new one and restart the sync
                    self.current_syncing_root_timestamp, self.current_syncing_root_hash = await self.consensus.get_closest_root_hash_consensus(int(time.time())-FAST_SYNC_CUTOFF_PERIOD)
                    if self.current_syncing_root_timestamp is not None:
                        self.chain_head_db.set_current_syncing_info(self.current_syncing_root_timestamp, self.current_syncing_root_hash)
    
            else:
                #look it up from db
                syncing_info = self.chain_head_db.get_current_syncing_info()
                self.logger.debug("syncing_info: {}".format(syncing_info))
                if syncing_info == None:
                    self.current_syncing_root_timestamp, self.current_syncing_root_hash = await self.consensus.get_closest_root_hash_consensus(int(time.time())-FAST_SYNC_CUTOFF_PERIOD)
                    self.head_hash_of_last_chain = ZERO_HASH32
                    if self.current_syncing_root_timestamp is not None:
                        self.chain_head_db.set_current_syncing_info(self.current_syncing_root_timestamp, self.current_syncing_root_hash)
    
                        
                else:
                    timestamp = syncing_info.timestamp
                    root_hash = syncing_info.head_root_hash
                    head_hash_of_last_chain = syncing_info.head_hash_of_last_chain
                    
                    if timestamp < int(time.time()) - NUMBER_OF_HEAD_HASH_TO_SAVE*TIME_BETWEEN_HEAD_HASH_SAVE:
                        self.current_syncing_root_timestamp, self.current_syncing_root_hash = await self.consensus.get_closest_root_hash_consensus(int(time.time())-FAST_SYNC_CUTOFF_PERIOD)
                        if self.current_syncing_root_timestamp is not None:
                            self.chain_head_db.set_current_syncing_info(self.current_syncing_root_timestamp, self.current_syncing_root_hash)
                    
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
                    self.logger.debug("checking peer timeouts, chain_request_timestamp = {}, timeout time = {}".format(chain_request_info.timestamp_sent, (int(time.time()) - self._reply_timeout)))
                    if chain_request_info.timestamp_sent < int(time.time()) - self._reply_timeout:
                        
                        #delete the request
                        self.failed_chain_requests[chain_request_wallet_address] = chain_request_info
                        del(self.pending_chain_requests[chain_request_wallet_address])
                        #re-queue peer
                        self.register_peer(chain_request_info.peer)
                        self.logger.debug("Requeuing a peer")
                        
                
            await asyncio.sleep(self._reply_timeout)
       

    #send a request to a peer asking for the next chain. if it is not found, then it must be older. it cant be newer because of how we initialized sync.
        
    async def send_chain_requests(self):
        while not self._sync_complete.is_set() and self.is_running:
            peer = await self.wait(self._idle_peers_in_consensus.get())
            if peer.is_running:
                self.logger.debug("Found a peer to send chain requests to")
            else:
                self.logger.info("%s disconnected, aborting sync", peer)
                break
            
            with await self.writing_chain_request_vars:
                #first check if any requests failed, and send them out again
                failed_chain_requests = list(self.failed_chain_requests.values())
                if len(failed_chain_requests) > 0:
                    shuffle(failed_chain_requests)
                    window_start = failed_chain_requests[0].window_start
                    window_length = failed_chain_requests[0].window_length
                    head_hash_of_last_chain = failed_chain_requests[0].head_hash_of_last_chain
                    del(self.failed_chain_requests[failed_chain_requests[0].peer.wallet_address])
                    self.logger.debug("Resending failed chain request")
                else:
                    if self.received_final_chain.is_set():
                        #only send new chain requests if we havent gotten to the final one, or if we are re-requesting a failed request.
                        break
                    self.last_window_start = self.last_window_start + self.last_window_length
                    window_start = self.last_window_start
                    
                    self.last_window_length = NUM_CHAINS_TO_REQUEST
                    window_length = self.last_window_length
                
                    head_hash_of_last_chain = self.head_hash_of_last_chain
                self.logger.info("Sending chain request to {}, window_start {}, window_length {}".format(peer.wallet_address,window_start,window_length))
    
                new_chain_request_info = ChainRequestInfo(peer, 
                                                          self.current_syncing_root_timestamp, 
                                                          self.current_syncing_root_hash,
                                                          head_hash_of_last_chain, 
                                                          window_start, 
                                                          window_length, 
                                                          timestamp_sent = int(time.time()))
                peer.sub_proto.send_get_chains_syncing(new_chain_request_info)
                self.pending_chain_requests[peer.wallet_address] = new_chain_request_info
       

#    async def _process_headers(self, peer: HLSPeer, headers: List[BlockHeader]) -> int:
#        start = time.time()
#        target_td = await self._calculate_td(headers)
#        await self._download_block_parts(
#            target_td,
#            [header for header in headers if not _is_body_empty(header)],
#            self.request_bodies,
#            self._downloaded_bodies,
#            _body_key,
#            'body')
#        self.logger.debug("Got block bodies for chain segment")
#
#        missing_receipts = [header for header in headers if not _is_receipts_empty(header)]
#        # Post-Byzantium blocks may have identical receipt roots (e.g. when they have the same
#        # number of transactions and all succeed/failed: ropsten blocks 2503212 and 2503284),
#        # so we do this to avoid requesting the same receipts multiple times.
#        missing_receipts = list(unique(missing_receipts, key=_receipts_key))
#        await self._download_block_parts(
#            target_td,
#            missing_receipts,
#            self.request_receipts,
#            self._downloaded_receipts,
#            _receipts_key,
#            'receipt')
#        self.logger.debug("Got block receipts for chain segment")
#
#        # FIXME: Get the bodies returned by self._download_block_parts above and use persit_block
#        # here.
#        for header in headers:
#            await self.wait(self.chaindb.coro_persist_header(header))
#
#        head = await self.wait(self.chaindb.coro_get_canonical_head())
#        self.logger.info(
#            "Imported %d headers in %0.2f seconds, new head: #%d (%s)",
#            len(headers),
#            time.time() - start,
#            head.block_number,
#            encode_hex(head.hash)[2:8],
#        )
#        # Quite often the header batch we receive here includes headers past the peer's reported
#        # head (via the NewBlock msg), so we can't compare our head's hash to the peer's in
#        # order to see if the sync is completed. Instead we just check that we have the peer's
#        # head_hash in our chain.
#        try:
#            await self.wait(self.chaindb.coro_get_block_header_by_hash(peer.head_hash))
#        except HeaderNotFound:
#            pass
#        else:
#            self.logger.info("Fast sync with %s completed", peer)
#            self._sync_complete.set()
#
#        return head.block_number
#
#    async def _download_block_parts(
#            self,
#            target_td: int,
#            headers: List[BlockHeader],
#            request_func: Callable[[int, List[BlockHeader]], int],
#            download_queue: 'asyncio.Queue[Tuple[HLSPeer, List[DownloadedBlockPart]]]',
#            key_func: Callable[[BlockHeader], Union[bytes, Tuple[bytes, bytes]]],
#            part_name: str) -> 'List[DownloadedBlockPart]':
#        """Download block parts for the given headers, using the given request_func.
#
#        Retry timed out parts until we have the parts for all headers.
#
#        Raises NoEligiblePeers if at any moment we have no connected peers that have the blocks
#        we want.
#        """
#        missing = headers.copy()
#        # The ETH protocol doesn't guarantee that we'll get all body parts requested, so we need
#        # to keep track of the number of pending replies and missing items to decide when to retry
#        # them. See request_receipts() for more info.
#        pending_replies = request_func(target_td, missing)
#        parts: List[DownloadedBlockPart] = []
#        while missing:
#            if pending_replies == 0:
#                pending_replies = request_func(target_td, missing)
#
#            try:
#                peer, received = await self.wait(
#                    download_queue.get(),
#                    timeout=self._reply_timeout)
#            except TimeoutError:
#                pending_replies = request_func(target_td, missing)
#                continue
#
#            received_keys = set([part.unique_key for part in received])
#
#            duplicates = received_keys.intersection(part.unique_key for part in parts)
#            unexpected = received_keys.difference(key_func(header) for header in headers)
#
#            parts.extend(received)
#            pending_replies -= 1
#
#            if unexpected:
#                self.logger.debug("Got unexpected %s from %s: %s", part_name, peer, unexpected)
#            if duplicates:
#                self.logger.debug("Got duplicate %s from %s: %s", part_name, peer, duplicates)
#
#            missing = [
#                header
#                for header in missing
#                if key_func(header) not in received_keys
#            ]
#
#        return parts
#
#    def _request_block_parts(
#            self,
#            target_td: int,
#            headers: List[BlockHeader],
#            request_func: Callable[[HLSPeer, List[BlockHeader]], None]) -> int:
#        eligible_peers = [
#            peer for peer in self.peer_pool.peers if cast(HLSPeer, peer).head_td >= target_td]
#        if not eligible_peers:
#            raise NoEligiblePeers()
#        length = math.ceil(len(headers) / len(eligible_peers))
#        batches = list(partition_all(length, headers))
#        for peer, batch in zip(eligible_peers, batches):
#            request_func(cast(HLSPeer, peer), batch)
#        return len(batches)
#
#    def _send_get_block_bodies(self, peer: HLSPeer, headers: List[BlockHeader]) -> None:
#        self.logger.debug("Requesting %d block bodies to %s", len(headers), peer)
#        peer.sub_proto.send_get_block_bodies([header.hash for header in headers])
#
#    def _send_get_receipts(self, peer: HLSPeer, headers: List[BlockHeader]) -> None:
#        self.logger.debug("Requesting %d block receipts to %s", len(headers), peer)
#        peer.sub_proto.send_get_receipts([header.hash for header in headers])
#
#    def request_bodies(self, target_td: int, headers: List[BlockHeader]) -> int:
#        """Ask our peers for bodies for the given headers.
#
#        See request_receipts() for details of how this is done.
#        """
#        return self._request_block_parts(target_td, headers, self._send_get_block_bodies)

#    def request_receipts(self, target_td: int, headers: List[BlockHeader]) -> int:
#        """Ask our peers for receipts for the given headers.
#
#        We partition the given list of headers in batches and request each to one of our connected
#        peers. This is done because geth enforces a byte-size cap when replying to a GetReceipts
#        msg, and we then need to re-request the items that didn't fit, so by splitting the
#        requests across all our peers we reduce the likelyhood of having to make multiple
#        serialized requests to ask for missing items (which happens quite frequently in practice).
#
#        Returns the number of requests made.
#        """
#        return self._request_block_parts(target_td, headers, self._send_get_receipts)

    async def _cleanup(self) -> None:
        # We don't need to cancel() anything, but we yield control just so that the coroutines we
        # run in the background notice the cancel token has been triggered and return.
        await asyncio.sleep(0)

    async def _handle_msg(self, peer: HLSPeer, cmd: protocol.Command,
                          msg: protocol._DecodedMsgType) -> None:
#        if isinstance(cmd, hls.BlockHeaders):
#            self._handle_block_headers(list(cast(Tuple[BlockHeader], msg)))
#            
#        elif isinstance(cmd, hls.BlockBodies):
#            await self._handle_block_bodies(peer, list(cast(Tuple[BlockBody], msg)))
#        elif isinstance(cmd, hls.Receipts):
#            await self._handle_block_receipts(peer, cast(List[List[Receipt]], msg))
#        elif isinstance(cmd, hls.NewBlock):
#            await self._handle_new_block(peer, cast(Dict[str, Any], msg))
#        elif isinstance(cmd, hls.GetBlockHeaders):
#            await self._handle_get_block_headers(peer, cast(Dict[str, Any], msg))
        if isinstance(cmd, hls.GetChainsSyncing):
            await self._handle_get_chains_syncing(peer, cast(Dict[str, Any], msg))
        elif isinstance(cmd, hls.Chain):
            await self._handle_chain(peer, cast(Dict[str, Any], msg))
        else:
            #self.logger.debug("Ignoring %s message from %s: msg %r", cmd, peer, msg)
            pass


#    def _handle_block_headers(self, headers: List[BlockHeader]) -> None:
#        if not headers:
#            self.logger.warn("Got an empty BlockHeaders msg")
#            return
#        self.logger.debug(
#            "Got BlockHeaders from %d to %d", headers[0].block_number, headers[-1].block_number)
#        self._new_headers.put_nowait(headers)

#    async def _handle_new_block(self, peer: HLSPeer, msg: Dict[str, Any]) -> None:
#        header = msg['block'][0]
#        actual_head = header.parent_hash
#        actual_td = msg['total_difficulty'] - header.difficulty
#        if actual_td > peer.head_td:
#            peer.head_hash = actual_head
#            peer.head_td = actual_td
#            self._sync_requests.put_nowait(peer)

#    async def _handle_block_receipts(self,
#                                     peer: HLSPeer,
#                                     receipts_by_block: List[List[hls.Receipt]]) -> None:
#        self.logger.debug("Got Receipts for %d blocks from %s", len(receipts_by_block), peer)
#        loop = asyncio.get_event_loop()
#        iterator = map(make_trie_root_and_nodes, receipts_by_block)
#        # The map() call above is lazy (it returns an iterator! ;-), so it's only evaluated in
#        # the executor when the list() is applied to it.
#        receipts_tries = await self.wait(loop.run_in_executor(self._executor, list, iterator))
#        downloaded: List[DownloadedBlockPart] = []
#        for (receipts, (receipt_root, trie_dict_data)) in zip(receipts_by_block, receipts_tries):
#            await self.wait(self.chaindb.coro_persist_trie_data_dict(trie_dict_data))
#            downloaded.append(DownloadedBlockPart(receipts, receipt_root))
#        self._downloaded_receipts.put_nowait((peer, downloaded))
#
#    async def _handle_block_bodies(self,
#                                   peer: HLSPeer,
#                                   bodies: List[hls.BlockBody]) -> None:
#        self.logger.debug("Got Bodies for %d blocks from %s", len(bodies), peer)
#        loop = asyncio.get_event_loop()
#        iterator = map(make_trie_root_and_nodes, [body.transactions for body in bodies])
#        # The map() call above is lazy (it returns an iterator! ;-), so it's only evaluated in
#        # the executor when the list() is applied to it.
#        transactions_tries = await self.wait(
#            loop.run_in_executor(self._executor, list, iterator))
#        downloaded: List[DownloadedBlockPart] = []
#        for (body, (tx_root, trie_dict_data)) in zip(bodies, transactions_tries):
#            await self.wait(self.chaindb.coro_persist_trie_data_dict(trie_dict_data))
#            uncles_hash = await self.wait(self.chaindb.coro_persist_uncles(body.uncles))
#            downloaded.append(DownloadedBlockPart(body, (tx_root, uncles_hash)))
#        self._downloaded_bodies.put_nowait((peer, downloaded))

#    async def _handle_get_block_headers(self,
#                                        peer: HLSPeer,
#                                        header_request: Dict[str, Any]) -> None:
#        self.logger.debug("Peer %s made header request: %s", peer, header_request)
#        # TODO: We should *try* to return the requested headers as they *may*
#        # have already been synced into our chain database.
#        peer.sub_proto.send_block_headers([])
        
    async def _handle_get_chains_syncing(self,
                                        peer: HLSPeer,
                                        chain_request: Dict[str, Any]) -> None:
        self.logger.debug("Peer %s made chains syncing request: %s", peer.wallet_address, chain_request)
        
        next_head_hashes = await self.chain_head_db.coro_get_next_n_head_block_hashes(chain_request['head_hash_of_last_chain'],
                                                                                      chain_request['window_start'], 
                                                                                      chain_request['window_length'],
                                                                                      root_hash = chain_request['head_root_hash'])
        if len(next_head_hashes) < chain_request['window_length']:
            contains_last_chain = True
        else:
            contains_last_chain = False
            
        is_last_chain = False
        
        if next_head_hashes is not None:
            for head_hash in next_head_hashes:
                
                        
                chain_address = await self.chaindb.coro_get_chain_wallet_address_for_block_hash(self.base_db, head_hash)
                #whole_chain = await self.chaindb.coro_get_all_blocks_on_chain(self.chain.get_vm().get_block_class(), chain_address)
                whole_chain = await self.chaindb.coro_get_all_blocks_on_chain(P2PBlock, chain_address)
                
                if contains_last_chain:
                    if head_hash == next_head_hashes[-1]:
                        is_last_chain = True
                    
                peer.sub_proto.send_chain(whole_chain, is_last_chain)
                self.logger.debug("sending chain with chain address {}, is_last? {}".format(chain_address, is_last_chain))
                
    async def _handle_chain(self,
                                        peer: HLSPeer,
                                        msg: Dict[str, Any]) -> None:

        
        with await self.writing_chain_request_vars:
            try:
                num_chains_expected = self.pending_chain_requests[peer.wallet_address].window_length
                #update the timestamp so that it doesnt time out.
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
            
            #now lets save it to database overwriting any chain that we have
            self.logger.debug("importing chain now")
            await self.chain.coro_import_chain(block_list = msg['blocks'], save_block_head_hash_timestamp = False)
            try:
                self.num_chains_returned_in_incomplete_requests[peer.wallet_address] += 1
            except KeyError:
                self.num_chains_returned_in_incomplete_requests[peer.wallet_address] = 1
                
            if self.num_chains_returned_in_incomplete_requests[peer.wallet_address] == num_chains_expected:
                del(self.pending_chain_requests[peer.wallet_address])
                del(self.num_chains_returned_in_incomplete_requests[peer.wallet_address])
                self.register_peer(peer)
            
            
            if msg['is_last'] == True:
                #if this is set, we won't receive any more chains from this peer 
                #even if we havent received the number of chains we asked for
                del(self.pending_chain_requests[peer.wallet_address])
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
    
    def __init__(self,*args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        
        self._initial_sync_complete = asyncio.Event()
        #[(new_chronological_blocks, final_root_hash),...]
        self._new_chronological_block_window = asyncio.Queue()
        
        self.chain_head_db.load_saved_root_hash()


    async def _run(self) -> None:
        self.logger.debug("Starting regular chainsyncer. waiting for consensus and chain config to initialize.")

        consensus_ready = await self.consensus.coro_is_ready.wait()
        if consensus_ready:
            self.logger.debug('waiting for consensus min gas system ready')
            min_gas_system_ready = await self.consensus.coro_min_gas_system_ready.wait()
            if min_gas_system_ready:
                self.logger.debug("consensus ready")
                with self.subscribe(self.peer_pool):
                    self.logger.debug("syncing chronological blocks")
                    #await self.sync_chronological_blocks()
                    asyncio.ensure_future(self._handle_msg_loop())
                    asyncio.ensure_future(self._handle_import_block_loop())
                    
                    #this runs forever
                    asyncio.ensure_future(self.sync_historical_root_hash_with_consensus())
                    #asyncio.ensure_future(self.re_queue_timeout_peers())
                    await self.sync_block_conflict_with_consensus()
    
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
                await self.handle_new_block(new_block = new_block_queue_item.new_block,
                                            chain_address = new_block_queue_item.chain_address,
                                            peer = new_block_queue_item.peer,
                                            propogate_to_network = new_block_queue_item.propogate_to_network,
                                            from_rpc = new_block_queue_item.from_rpc)
            except OperationCancelled:
                # Silently swallow OperationCancelled exceptions because we run unsupervised (i.e.
                # with ensure_future()). Our caller will also get an OperationCancelled anyway, and
                # there it will be handled.
                pass
            except Exception:
                self.logger.exception("Unexpected error when importing block from %s", new_block_queue_item.peer)

    async def does_local_blockchain_database_match_consensus(self):
        try:
            consensus_root_hash, latest_good_timestamp_before_conflict = await self.consensus.get_latest_root_hash_before_conflict()
            if latest_good_timestamp_before_conflict is None:
                return True
            else:
                return False
        except DatabaseResyncRequired:
            self.logger.debug("Our database has been offline for too long. Need to perform fast sync again. Database should be deleted and program should be restarted. ")
            #input("Press Enter to continue if you would like to do this, otherwise force close the program.")
            #self.base_db.destroy_db()
        

        
    async def sync_block_conflict_with_consensus(self):
        self.logger.debug("sync_block_conflict_with_consensus starting")
        while True:
            self.logger.debug("sync_historical_root_hash_with_consensus loop start")
            block_conflict_choices_to_change = await self.consensus.get_correct_block_conflict_choice_where_we_differ_from_consensus()
            if block_conflict_choices_to_change is not None:
                #save this so that we know to replace our local block when this one is sent to us.
                self._latest_block_conflict_choices_to_change = set(block_conflict_choices_to_change)
                self.logger.debug("block conflict syncer found blocks that need changing.")
                
                for block_conflict_choice in block_conflict_choices_to_change:
                    peers_with_block = self.consensus.get_peers_who_have_conflict_block(block_conflict_choice.block_hash)
                    peers_sorted_by_stake = self.peer_pool.sort_peers_by_stake(peers = peers_with_block)
                    
                    self.logger.debug("asking a peer for the consensus version of a conflict block that we have")
                    peers_sorted_by_stake[-1].sub_proto.send_get_chain_segment(block_conflict_choice.chain_address, block_conflict_choice.block_number)
                    
            await asyncio.sleep(CONSENSUS_SYNC_TIME_PERIOD) 

    async def sync_historical_root_hash_with_consensus(self):
        self.logger.debug("sync_historical_root_hash_with_consensus starting")
        while True:
            self.logger.debug("sync_historical_root_hash_with_consensus loop start")
            #this loop can continuously look at the root hashes in consensus, if they dont match ours then we need to update to the new one
            #it also has to look at conflict blocks and make sure we always have the one that is in consensus.
#            if not self._initial_sync_complete.is_set():
#                self.logger.debug("within sync_with_consensus loop. _initial_sync_complete not set, so running sync_chronological_blocks")
#                self.sync_chronological_blocks()
              
            try:
                consensus_root_hash, latest_good_timestamp = await self.consensus.get_latest_root_hash_before_conflict(before_timestamp = time.time()-MOVING_WINDOW_WHERE_HISTORICAL_ROOT_HASH_NOT_SYNCED)
            except DatabaseResyncRequired:
                #this means none of our root hashes match consensus. We need to delete our entire database and do fast sync again
                self.logger.debug("Our database has been offline for too long. Need to perform fast sync again. Database should be deleted and program should be restarted. ")
                input("Press Enter to continue if you would like to do this, otherwise force close the program.")
                #self.base_db.destroy_db()
                sys.exit()
                
            #this is the latest one where we actually do match consensus. Now we re-sync up to the next one
            
            if consensus_root_hash is None:
                #here we find that we have no conflict with the database that we currently have. 
                #However, we havent checked to see if we have the most up to data database. Need to check here.
                last_synced_timestamp_local, _ = self.chain_head_db.get_latest_historical_root_hash()
                last_available_timestamp_from_peers = self.consensus.get_newest_peer_root_hash_timestamp()
                if last_available_timestamp_from_peers is None:
                    self.logger.debug("We have no peer root hashes to sync with")
                else:
                    if last_synced_timestamp_local < last_available_timestamp_from_peers:
                        self.logger.debug("local database is in consensus but not up to date. running sync_chronological_blocks")
                        self._initial_sync_complete.clear()
                        await self.sync_chronological_blocks()
                        
                    #if it is none, then we have no conflicts
                    self.logger.debug("no conflicts found")
                    await asyncio.sleep(CONSENSUS_SYNC_TIME_PERIOD)
            else:
                #We have conflicts, lets sync up one window, and let the loop continue to go through all windows
                #self.current_syncing_root_timestamp, self.current_syncing_root_hash = self.consensus.get_next_consensus_root_hash_after_timestamp_that_differs_from_local_at_timestamp(latest_good_timestamp)
                self.current_syncing_root_timestamp, self.current_syncing_root_hash = self.consensus.get_next_consensus_root_hash_after_timestamp(latest_good_timestamp)
                
                self.logger.debug("Conflict found. Syncing historical window for time {}".format(self.current_syncing_root_timestamp))
                #re-queue all peers so that we know which ones are in consensus
                self.re_register_peers()
                
                try:
                    peer = await self.wait(self._idle_peers_in_consensus.get(), timeout=CONSENSUS_SYNC_TIME_PERIOD)
                except TimeoutError:
                    self.logger.debug('sync_with_consensus timeout because there are no peers in consensus')
                    continue
                
                if peer.is_running:
                    self.logger.debug("Found a peer to sync with for sync_with_consensus = {}".format(peer.wallet_address))
                else:
                    self.logger.info("%s disconnected, aborting sync with this peer", peer)
                    continue
                
                #make sure the peer has data for this timestamp. We may already be up to date, and there just havent been transactions for a while
                sorted_dict_root_hashes = SortedDict(peer.chain_head_root_hashes)
                peer_timestamps = list(sorted_dict_root_hashes.keys())
                if peer_timestamps[-1] < self.current_syncing_root_timestamp:
                    self.logger.debug("Skipping sync_with_consensus with this peer they dont have the correct root hash timestamp")
                    continue
                
                try:
                    #we sync the chronological window that leads up to the one we are syncing
                    await self.sync_chronological_window(self.current_syncing_root_timestamp-TIME_BETWEEN_HEAD_HASH_SAVE, peer, new_window = False)
                except TimeoutError:
                    self.logger.debug('sync_chronological_blocks timeout')
                    self.register_peer(peer)
                    continue

#                except Exception as e:
#                    self.logger.debug('Uncaught exception {}'.format(e))
#                    #there was an error importing the blocks. this most likely means one of the blocks was invalid.
#                    #so lets re-request this block window from someone else.
#                    self.register_peer(peer)
#                    continue
            
            
                self.register_peer(peer)
            
        
    
    #run this once before running the main function that keeps our database up to date. 
    #we cannot import new blocks while this is running because it will save a new root hash           
    #TODO: on receive new block function, have a switch that checks if chronological blocks have run yet     
    async def sync_chronological_blocks(self):
        while not self._initial_sync_complete.is_set() and self.is_running:
            
            last_synced_timestamp, last_synced_root_hash = self.chain_head_db.get_latest_historical_root_hash()
            #last_synced_timestamp, last_synced_root_hash = self.chain_head_db.get_last_complete_historical_root_hash()
            if last_synced_timestamp > time.time():
                self.logger.debug("finished chronological block sync 3")
                self._initial_sync_complete.set()
                return
            

            self.logger.debug("{}, {}".format(last_synced_timestamp, self.consensus.get_newest_peer_root_hash_timestamp()))
            if last_synced_timestamp >= self.consensus.get_newest_peer_root_hash_timestamp():
                self.logger.debug("finished chronological block sync 2")
                self._initial_sync_complete.set()
                return

            
            timestamp_to_check_peer_consensus, root_hash_to_check_peer_consensus = self.consensus.get_next_consensus_root_hash_after_timestamp_that_differs_from_local_at_timestamp(last_synced_timestamp)
            
            self.current_syncing_root_timestamp, self.current_syncing_root_hash = timestamp_to_check_peer_consensus, root_hash_to_check_peer_consensus
            #re-register peers so we know which ones are in consensus
            
            self.re_register_peers()
            
            peer = await self.wait(self._idle_peers_in_consensus.get())
            if peer.is_running:
                self.logger.debug("Found a peer to send chronological block requests to. peer wallet address = {}".format(peer.wallet_address))
            else:
                self.logger.info("%s disconnected, aborting sync with this peer", peer)
                continue
                
            
            #make sure the peer has data for this timestamp. We may already be up to date, and there just havent been transactions for a while
            sorted_list_root_hashes = SortedList(peer.chain_head_root_hashes)

            if sorted_list_root_hashes[-1][0] <= (self.current_syncing_root_timestamp-TIME_BETWEEN_HEAD_HASH_SAVE):
                self.logger.debug("Skipping chronological block sync with this peer because they don't have any newer blocks and dont match our latest imported window")
                continue
            try:
                await self.sync_chronological_window(self.current_syncing_root_timestamp-TIME_BETWEEN_HEAD_HASH_SAVE, peer, new_window = True)
            except TimeoutError:
                self.logger.debug('sync_chronological_blocks timeout')
                self.register_peer(peer)
                continue
            except LocalRootHashNotAsExpected:
                self.register_peer(peer)
                continue
            except Exception as e:
                self.logger.debug('Uncaught exception {}'.format(e))
                #there was an error importing the blocks. this most likely means one of the blocks was invalid.
                #so lets re-request this block window from someone else.
                self.register_peer(peer)
                continue
              
            
            
            self.register_peer(peer)
            
            
    
    async def sync_chronological_window(self, window_start_timestamp, peer, new_window = False):
        #we can now download the chronological blocks for this window, and then save the root hash for the next window
            
        peer.sub_proto.send_get_chronological_block_window(window_start_timestamp)

        new_chronological_blocks, final_root_hash = await self.wait(
            self._new_chronological_block_window.get(),
            token=peer.cancel_token,
            timeout=self._reply_timeout)
        
        #as long as these blocks are all newer than self.current_syncing_root_timestamp, then we dont need to worry about conflicts because
        #we cant have any blocks in this range of time yet.
#        window_start_timestamp, save_block_head_hash_timestamp = True, allow_unprocessed=False):
#        if len(new_chronological_blocks) > 0:
#            self.logger.debug("AAAAAAAAAAAA importing chronological window  {}".format(window_start_timestamp))

        chain = self.node.get_new_chain()

        chain.import_chronological_block_window(new_chronological_blocks,
                                                         window_start_timestamp = window_start_timestamp,
                                                         save_block_head_hash_timestamp = True, 
                                                         allow_unprocessed=True)
#        for block in new_chronological_blocks:
#            wallet_address = self.chaindb.get_chain_wallet_address_for_block(block)
#            await self.chain.coro_import_block(block, wallet_address = wallet_address, save_block_head_hash_timestamp = save_block_head_hash_timestamp, allow_unprocessed=False)
        
#        if new_window:
#            #if it is a new window, our chain head hash should match the expected one, and if so, we can save it to chain head db.
#            #we need to chainheaddb because the database was modified by the chain process.
#            self.chain_head_db.load_saved_root_hash()
#            local_head_root_hash = self.chain_head_db.get_root_hash()
#            if local_head_root_hash != final_root_hash:
#                self.logger.debug("root hash is not as expected after importing chronological block window. will re-request window. local: {}, expected: {}".format(local_head_root_hash,final_root_hash))
#                raise LocalRootHashNotAsExpected()
#                
#            else:
#                self.logger.debug('sync_chronological_blocks saving new root hash, root_hash = {}, timestamp = {}'.format(local_head_root_hash,window_start_timestamp+TIME_BETWEEN_HEAD_HASH_SAVE))
#                self.chain_head_db.save_single_historical_root_hash(local_head_root_hash, window_start_timestamp+TIME_BETWEEN_HEAD_HASH_SAVE)
#        else:
        #we need to chainheaddb because the database was modified by the chain process.
        #self.chain_head_db.load_saved_root_hash()
        local_head_root_hash = self.chain_head_db.get_historical_root_hash(self.current_syncing_root_timestamp)
#        full_root_hash_list = self.chain_head_db.get_historical_root_hashes(after_timestamp = self.current_syncing_root_timestamp-10000)
#        self.logger.debug("here are the root hashes around that time {}".format(full_root_hash_list))
        if local_head_root_hash != final_root_hash:
            self.logger.debug("root hash is not as expected after importing chronological block window for timestamp {}. will re-request window. local: {}, expected: {}".format(window_start_timestamp+TIME_BETWEEN_HEAD_HASH_SAVE, local_head_root_hash,final_root_hash))
            raise LocalRootHashNotAsExpected()
        
        
    async def _handle_msg(self, peer: HLSPeer, cmd: protocol.Command,
                          msg: protocol._DecodedMsgType) -> None:
        if isinstance(cmd, hls.NewBlock):
            await self._handle_new_block(peer, cast(Dict[str, Any], msg))
        elif isinstance(cmd, hls.GetBlockHeaders):
            await self._handle_get_block_headers(peer, cast(Dict[str, Any], msg))
        elif isinstance(cmd, hls.GetBlockBodies):
            await self._handle_get_block_bodies(peer, cast(List[Hash32], msg))
        elif isinstance(cmd, hls.GetReceipts):
            await self._handle_get_receipts(peer, cast(List[Hash32], msg))
        elif isinstance(cmd, hls.GetNodeData):
            self._handle_get_node_data(peer, cast(List[Hash32], msg))
        elif isinstance(cmd, hls.GetChronologicalBlockWindow):
            await self._handle_get_chronological_block_window(peer, cast(Dict[str, Any], msg))
        elif isinstance(cmd, hls.ChronologicalBlockWindow):
            await self._handle_chronological_block_window(peer, cast(Dict[str, Any], msg))
        elif isinstance(cmd, hls.GetChainSegment):
            await self._handle_get_chain_segment(peer, cast(Dict[str, Any], msg))
        elif isinstance(cmd, hls.Chain):
            await self._handle_chain(peer, cast(Dict[str, Any], msg))    

                    
#    async def re_queue_timeout_peers(self):
#        while not self._sync_complete.is_set() and self.is_running:
#            with await self.writing_chain_request_vars:
#                for chain_request_wallet_address, chain_request_info in self.pending_chain_requests.copy().items():
#                    self.logger.debug("checking peer timeouts, chain_request_timestamp = {}, timeout time = {}".format(chain_request_info.timestamp_sent, (int(time.time()) - REPLY_TIMEOUT)))
#                    if chain_request_info.timestamp_sent < int(time.time()) - REPLY_TIMEOUT:
#                        
#                        #delete the request
#                        self.failed_chain_requests[chain_request_wallet_address] = chain_request_info
#                        del(self.pending_chain_requests[chain_request_wallet_address])
#                        #re-queue peer
#                        self.register_peer(chain_request_info.peer)
#                        self.logger.debug("Requeuing a peer")
#                        
#                
#            await asyncio.sleep(REPLY_TIMEOUT)  
                

    async def _handle_get_chronological_block_window(self, peer: HLSPeer, msg: Dict[str, Any]) -> None:
        self.logger.debug("_handle_get_chronological_block_window")
        start_timestamp = msg['start_timestamp']
        final_root_hash = self.chain_head_db.get_historical_root_hash(start_timestamp+TIME_BETWEEN_HEAD_HASH_SAVE)
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
         
        
    async def _handle_get_block_headers(self, peer: HLSPeer, msg: Dict[str, Any]) -> None:
        block_number_or_hash = msg['block_number_or_hash']
        if isinstance(block_number_or_hash, bytes):
            header = await self.wait(
                self.chaindb.coro_get_block_header_by_hash(cast(Hash32, block_number_or_hash)))
            block_number = header.block_number
        elif isinstance(block_number_or_hash, int):
            block_number = block_number_or_hash
        else:
            raise TypeError(
                "Unexpected type for 'block_number_or_hash': %s", type(block_number_or_hash))
        limit = max(msg['max_headers'], hls.MAX_HEADERS_FETCH)
        if msg['reverse']:
            block_numbers = list(reversed(range(max(0, block_number - limit), block_number + 1)))
        else:
            head = await self.wait(self.chaindb.coro_get_canonical_head())
            head_number = head.block_number
            block_numbers = list(range(block_number, min(head_number + 1, block_number + limit)))
        headers = [
            await self.wait(
                self.chaindb.coro_get_canonical_block_header_by_number(cast(BlockNumber, i)))
            for i in block_numbers
        ]
        peer.sub_proto.send_block_headers(headers)

    async def _handle_get_block_bodies(self, peer: HLSPeer, msg: List[Hash32]) -> None:
        bodies = []
        # Only serve up to hls.MAX_BODIES_FETCH items in every request.
        hashes = msg[:hls.MAX_BODIES_FETCH]
        for block_hash in hashes:
            header = await self.wait(self.chaindb.coro_get_block_header_by_hash(block_hash))
            transactions = await self.wait(
                self.chaindb.coro_get_block_transactions(header, P2PTransaction))
            uncles = await self.wait(self.chaindb.coro_get_block_uncles(header.uncles_hash))
            bodies.append(BlockBody(transactions, uncles))
        peer.sub_proto.send_block_bodies(bodies)

    async def _handle_get_receipts(self, peer: HLSPeer, msg: List[Hash32]) -> None:
        receipts = []
        # Only serve up to hls.MAX_RECEIPTS_FETCH items in every request.
        hashes = msg[:hls.MAX_RECEIPTS_FETCH]
        for block_hash in hashes:
            header = await self.wait(self.chaindb.coro_get_block_header_by_hash(block_hash))
            receipts.append(await self.wait(self.chaindb.coro_get_receipts(header, Receipt)))
        peer.sub_proto.send_receipts(receipts)

    def _handle_get_node_data(self, peer: HLSPeer, msg: List[Hash32]) -> None:
        nodes = []
        for node_hash in msg:
            # FIXME: Need to use an async API here as well? chaindb.coro_get()?
            node = self.chaindb.db[node_hash]
            nodes.append(node)
        peer.sub_proto.send_node_data(nodes)

    async def _process_headers(self, peer: HLSPeer, headers: List[BlockHeader]) -> int:
        # This is needed to ensure after a state sync we only start importing blocks on top of our
        # current head, as that's the only one whose state root is present in our DB.
        for header in headers.copy():
            try:
                await self.wait(self.chaindb.coro_get_block_header_by_hash(header.hash))
            except HeaderNotFound:
                break
            else:
                headers.remove(header)
        else:
            head = await self.wait(self.chaindb.coro_get_canonical_head())
            return head.block_number

        target_td = await self._calculate_td(headers)
        downloaded_parts = await self._download_block_parts(
            target_td,
            [header for header in headers if not _is_body_empty(header)],
            self.request_bodies,
            self._downloaded_bodies,
            _body_key,
            'body')
        self.logger.info("Got block bodies for chain segment")

        parts_by_key = dict((part.unique_key, part.part) for part in downloaded_parts)
        for header in headers:
            vm_class = self.chain.get_vm_class_for_block_number(header.block_number)
            block_class = vm_class.get_block_class()

            if _is_body_empty(header):
                transactions: List[BaseTransaction] = []
                uncles: List[BlockHeader] = []
            else:
                body = cast(hls.BlockBody, parts_by_key[_body_key(header)])
                tx_class = block_class.get_transaction_class()
                transactions = [tx_class.from_base_transaction(tx)
                                for tx in body.transactions]
                uncles = body.uncles

            block = block_class(header, transactions, uncles)
            t = time.time()
            # FIXME: Instead of using self.wait() here we should pass our cancel_token to
            # coro_import_block() so that it can cancel the actual import-block task. See
            # https://github.com/ethereum/py-evm/issues/665 for details.
            await self.wait(self.chain.coro_import_block(block, perform_validation=True))
            self.logger.info("Imported block %d (%d txs) in %f seconds",
                             block.number, len(transactions), time.time() - t)

        head = await self.wait(self.chaindb.coro_get_canonical_head())
        self.logger.info("Imported chain segment, new head: #%d", head.block_number)
        return head.block_number
    
    async def _handle_get_chain_segment(self,
                                        peer: HLSPeer,
                                        msg: Dict[str, Any]) -> None:
        
#        data = {
#            'chain_address': chain_address,
#            'block_number_start': block_number_start,
#            'block_number_end': block_number_end,
#            }
        
        self.logger.debug("Peer %s made chains segment request: %s", peer.wallet_address, msg)
        
              
        chain_address = msg['chain_address']
        
        #whole_chain = await self.chaindb.coro_get_all_blocks_on_chain(self.chain.get_vm().get_block_class(), chain_address)
        chain_segment = await self.chaindb.coro_get_blocks_on_chain(P2PBlock, msg['block_number_start'], msg['block_number_end'], chain_address)
        
        peer.sub_proto.send_chain(chain_segment, True)
        
        self.logger.debug("sending chain with chain address {}".format(chain_address))
        
    
    async def _handle_chain(self,
                                        peer: HLSPeer,
                                        msg: Dict[str, Any]) -> None:
        self.logger.debug("received new chain")
        block_list = msg['blocks']
        
        #in this mode, we can only import a chain if we already have the parent,
        #or if it starts from block 0. In both cases, we can get the chain wallet address
        #from the parent, or from the sender of block 0
        
        try:
            chain_address = self.chaindb.get_chain_wallet_address_for_block(block_list[0])
        except ValueError:
            #this means we don't have the correct parent.
            #the procedure is: send head block, if they don't have the parent, they request the missing blocks beyond the local head, 
            #and if more than 1, then they come as a chain here. So we must have a block that corresponds to the parent or else this
            #is a conflict block.... we should add the parent to conflict blocks, but we dont know what chain it belongs to...
            return
            
        i = 1
        for new_block in block_list:
            if i == len(block_list):
                propogate_to_network = True
            else:
                propogate_to_network = False
                
            success = await self.handle_new_block(new_block, chain_address, propogate_to_network = propogate_to_network)
            if success == False:
                #if one block fails to be imported, no point in importing the rest because they will fail or call this function again
                #creating an infinite loop.
                break
            
            i += 1

    
    async def _handle_new_block(self,peer: HLSPeer,
                                    msg: Dict[str, Any]) -> None:

        self.logger.debug('received new block from network. processing')
        new_block = msg['block']
        chain_address = msg['chain_address']
        queue_item = NewBlockQueueItem(new_block=new_block, chain_address = chain_address, peer=peer)
        self._new_blocks_to_import.put_nowait(queue_item)

        #await self.handle_new_block(new_block, chain_address, peer = peer)



    async def handle_new_block(self, new_block: P2PBlock, chain_address: bytes, peer: BasePeer = None, propogate_to_network: bool = True, from_rpc:bool = False):
        #TODO. Here we need to validate the block as much as we can. Try to do this in a way where we can run it in another process to speed it up.
        #No point in doing anything if the block is invalid.
        #or to speed up transaction throughput we could just rely on the import to validate.
        #if we do that, we just cant re-broadcast the blocks until we have successfully imported. So if the block goes to unprocessed
        #run the validator before sending out. lets make sure everything is validated in chain before saving as unprocessed.

        '''
        This returns true if the block is imported successfully, False otherwise
        If the block comes from RPC, we need to treat it differently. If it is invalid for any reason whatsoever, we just delete.
        '''
        self.logger.debug("handling new block")
        chain = self.node.get_new_chain()
        required_min_gas_price = self.chaindb.get_required_block_min_gas_price(new_block.header.timestamp)
        block_gas_price = int(get_block_average_transaction_gas_price(new_block))
        
        if block_gas_price < required_min_gas_price:
            self.logger.debug("New block didn't have high enough gas price. block_gas_price = {}, required_min_gas_price = {}".format(block_gas_price, required_min_gas_price))
            return False

        #Get the head of the chain that we have in the database
        #need this to see if we are replacing a block
        replacing_block_permitted = False
        try:
            canonical_head = self.chaindb.get_canonical_head(chain_address)
            
            #check to see if we are replacing a block
            if new_block.header.block_number <= canonical_head.block_number:
                #it is trying to replace a block that we already have.
                
                #is it the same as the one we already have?
                local_block_hash = self.chaindb.get_canonical_block_hash(new_block.header.block_number, chain_address) 
                if new_block.header.hash == local_block_hash:
                    #we already have this block. Do nothing. Do not propogate if we already have it.
                    self.logger.debug("We already have this block, doing nothing")
                    return True
                else:
                    #check to see if we are expecting this block because it is actually the new consensus block
                    if self._latest_block_conflict_choices_to_change is not None:
                        #we are actually expecting new blocks to overwrite. Lets check to see if this is one of them.
                        block_conflict_choice = BlockConflictChoice(chain_address, new_block.header.block_number, new_block.header.hash)
                        if block_conflict_choice in self._latest_block_conflict_choices_to_change:
                            replacing_block_permitted = True
                            self.logger.debug("Received a block conflict that we were expecting. going to import and replace ours.")
                    if not replacing_block_permitted:
                        #this is a conflict block. Send it to consensus and let the syncer do its thing.
                        if not from_rpc:
                            self.logger.debug("Received a conflicting block. sending to consensus as block conflict.")
                            self.consensus.add_block_conflict(chain_address, new_block.header.block_number)
                        return False

        except CanonicalHeadNotFound:
            #we have to download the entire chain
            canonical_head = None


        #deal with the possibility of missing blocks
        #it is only possible that we are missing previous blocks if this is not the genesis block
        if new_block.header.block_number > 0:
            if canonical_head is None or new_block.header.block_number > (canonical_head.block_number + 1):
                #we need to download missing blocks. 
                #lets keep it simple, just send this same peer a request for the new blocks that we need, plus this one again.
                
                if peer is not None:
                    if canonical_head is None:
                        block_number_start = 0
                    else:
                        block_number_start = canonical_head.block_number + 1
                    self.logger.debug('asking peer for the rest of missing chian')
                    peer.sub_proto.send_get_chain_segment(chain_address, block_number_start, new_block.header.block_number)
                    return False


        try:
            if new_block.header.block_number < 200:
                imported_block = await chain.coro_import_block(new_block,
                                                   wallet_address = chain_address,
                                                   allow_replacement = replacing_block_permitted)
            else:
                imported_block = chain.import_block_with_profiler(new_block,
                                                    wallet_address = chain_address,
                                                    allow_replacement = replacing_block_permitted)
                sys.exit()
        except ReplacingBlocksNotAllowed:
            if not from_rpc:
                #it has not been validated yet.
                self.logger.debug('ReplacingBlocksNotAllowed error. adding to block conflicts')
                chain.validate_block_specification(new_block)
                self.consensus.add_block_conflict(chain_address, new_block.header.block_number)
            return False
        except ParentNotFound:
            if not from_rpc:
                #it has not been validated yet
                self.logger.debug('ParentNotFound error. adding to block conflicts')
                chain.validate_block_specification(new_block)
                self.consensus.add_block_conflict(chain_address, new_block.header.block_number-1)
            return False
        except ValidationError as e:
            if not from_rpc:
                self.logger.debug('ValidationError error when importing block. Error: {}'.format(e))
            return False
        except ValueError as e:
            if not from_rpc:
                self.logger.debug('ValueError error when importing block. Error: {}'.format(e))
            return False
#        except Exception as e:
#            
#            self.logger.error('tried to import a block and got error {}'.format(e))
#            return
        
        if propogate_to_network:
            for loop_peer in self.peer_pool.peers:
                #don't send the block back to the peer who gave it to us.
                if loop_peer != peer:
                    self.logger.debug('sending new block to peer {}'.format(loop_peer))
                    loop_peer.sub_proto.send_new_block(imported_block, chain_address) 
        
        return True
        #check to make sure it meets the minimum gas requirements for the block timestamp.
        #if not, just delete it.
        #first, import block with allow_replacement = False. catch ReplacingBlocksNotAllowed(), which tells you it is a conflict.
        #it can also fail the import if some of the receive transactions are not found. it will save it as unprocessed. in this case, we need to validate it
        #allow unprocessed, then once the parents are received, it will process all children which is safe as long as allow_replacement is false.
        #if it is a conflict, we still need to make sure it is valid by checking: block signature, transaction signatures, transaction signature of send
        #transaction within the receive transactions. cant check if send tx exists because we could potentially receive them in the wrong order.
        #0) check if block is valid. if not, do nothing. if yes, send to all peers.
        #1) check to see if it conflicts with a block we already have
        #if yes, use consensus to figure out which one to keep. if no, import.
        #2) 

    ####################
    ###Testing functions
    ####################
    
    def propogate_block_to_network(self, block, chain_address):
        for peer in self.peer_pool.peers:
            self.logger.debug('sending test block to peer {}'.format(peer))
            peer.sub_proto.send_new_block(block, chain_address)
        
        
class DownloadedBlockPart(NamedTuple):
    part: Union[hls.BlockBody, List[Receipt]]
    unique_key: Union[bytes, Tuple[bytes, bytes]]


class NewBlockQueueItem:
    def __init__(self, new_block: P2PBlock, chain_address: bytes, peer: Union[BasePeer, None]=None, propogate_to_network:bool=True, from_rpc: bool=False):
        self.new_block = new_block
        self.chain_address = chain_address
        self.peer = peer
        self.propogate_to_network = propogate_to_network
        self.from_rpc = from_rpc

#NewBlockQueueItem = namedtuple(NewBlockQueueItem, 'new_block chain_address peer propogate_to_network from_rpc')

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


def _test() -> None:
    import argparse
    import signal
    from hp2p import ecies
    from hvm.chains.ropsten import RopstenChain, ROPSTEN_GENESIS_HEADER
    from hvm.db.backends.level import LevelDB
    from tests.p2p.integration_test_helpers import (
        FakeAsyncChainDB, FakeAsyncRopstenChain, LocalGHLSPeerPool, FakeAsyncHeaderDB)

    parser = argparse.ArgumentParser()
    parser.add_argument('-db', type=str, required=True)
    parser.add_argument('-fast', action="store_true")
    parser.add_argument('-local-geth', action="store_true")
    parser.add_argument('-debug', action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%H:%M:%S')
    log_level = logging.INFO
    if args.debug:
        log_level = logging.DEBUG
    logging.getLogger('hp2p.chain.ChainSyncer').setLevel(log_level)

    loop = asyncio.get_event_loop()

    base_db = LevelDB(args.db)
    chaindb = FakeAsyncChainDB(base_db)
    chaindb.persist_header(ROPSTEN_GENESIS_HEADER)
    headerdb = FakeAsyncHeaderDB(base_db)

    privkey = ecies.generate_privkey()
    if args.local_geth:
        peer_pool = LocalGHLSPeerPool(HLSPeer, headerdb, RopstenChain.network_id, privkey)
    else:
        from hp2p.peer import HardCodedNodesPeerPool
        discovery = None
        peer_pool = HardCodedNodesPeerPool(
            peer_class=HLSPeer,
            headerdb=headerdb,
            network_id=RopstenChain.network_id,
            privkey=privkey,
            discovery=discovery,
        )

    asyncio.ensure_future(peer_pool.run())
    if args.fast:
        syncer = FastChainSyncer(chaindb, peer_pool)
    else:
        chain = FakeAsyncRopstenChain(base_db)
        syncer = RegularChainSyncer(chain, chaindb, peer_pool)
    syncer.min_peers_to_sync = 1

    sigint_received = asyncio.Event()
    for sig in [signal.SIGINT, signal.SIGTERM]:
        loop.add_signal_handler(sig, sigint_received.set)

    async def exit_on_sigint():
        await sigint_received.wait()
        await peer_pool.cancel()
        await syncer.cancel()
        loop.stop()

    loop.set_debug(True)
    asyncio.ensure_future(exit_on_sigint())
    asyncio.ensure_future(syncer.run())
    loop.run_forever()
    loop.close()


if __name__ == "__main__":
    # Use the snippet below to get profile stats and print the top 50 functions by cumulative time
    # used.
    # import cProfile, pstats  # noqa
    # cProfile.run('_test()', 'stats')
    # pstats.Stats('stats').strip_dirs().sort_stats('cumulative').print_stats(50)
    _test()
