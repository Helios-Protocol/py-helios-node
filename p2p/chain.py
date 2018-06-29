import asyncio
import logging
import math
import operator
import time
from typing import (
    Any,
    Callable,
    Dict,
    List,
    NamedTuple,
    Tuple,
    Union,
    cast,
)

from cytoolz import (
    partition_all,
    unique,
)

from eth_typing import BlockNumber, Hash32
from eth_utils import (
    encode_hex,
)

from evm.constants import (
    BLANK_ROOT_HASH, 
    EMPTY_UNCLE_HASH, 
    GENESIS_PARENT_HASH,
    NUMBER_OF_HEAD_HASH_TO_SAVE,
    TIME_BETWEEN_HEAD_HASH_SAVE,
)
from evm.chains import AsyncChain
from evm.db.chain import AsyncChainDB
from evm.db.trie import make_trie_root_and_nodes
from evm.exceptions import HeaderNotFound
from evm.rlp.headers import BlockHeader
from evm.rlp.receipts import Receipt
from evm.rlp.transactions import BaseTransaction

from p2p.constants import (
    FAST_SYNC_CUTOFF_PERIOD,
    NUM_CHAINS_TO_REQUEST,
    REPLY_TIMEOUT,
)
from p2p import protocol
from p2p import eth
from p2p import hls
from p2p.cancel_token import CancelToken
from p2p.exceptions import NoEligiblePeers, OperationCancelled
from p2p.peer import BasePeer, HLSPeer, PeerPool, PeerPoolSubscriber
from p2p.rlp import BlockBody, P2PTransaction
from p2p.service import BaseService
from p2p.utils import (
    get_process_pool_executor,
)

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
    logger = logging.getLogger("p2p.chain.ChainSyncer")
    # We'll only sync if we are connected to at least min_peers_to_sync.
    min_peers_to_sync = 1
    # TODO: Instead of a fixed timeout, we should use a variable one that gets adjusted based on
    # the round-trip times from our download requests.
    _reply_timeout = 60
    current_syncing_root_timestamp = None
    current_syncing_root_hash = None
    head_hash_of_last_chain = None
    last_window_start = 0
    last_window_length = 0

    def __init__(self,
                 chain,
                 chaindb: AsyncChainDB,
                 chain_head_db,
                 peer_pool: PeerPool,
                 consensus,
                 token: CancelToken = None) -> None:
        super().__init__(token)
        self.consensus = consensus
        self.chain = chain
        self.chaindb = chaindb
        self.chain_head_db = chain_head_db
        self.peer_pool = peer_pool
        self._syncing = False
        self._sync_complete = asyncio.Event()
        self._sync_requests: asyncio.Queue[HLSPeer] = asyncio.Queue()
        self._idle_peers: asyncio.Queue[HLSPeer] = asyncio.Queue()
        self._idle_peers_in_consensus: asyncio.Queue[HLSPeer] = asyncio.Queue()
        self._new_headers: asyncio.Queue[List[BlockHeader]] = asyncio.Queue()
        # Those are used by our msg handlers and _download_block_parts() in order to track missing
        # bodies/receipts for a given chain segment.
        self._downloaded_receipts: asyncio.Queue[Tuple[HLSPeer, List[DownloadedBlockPart]]] = asyncio.Queue()  # noqa: E501
        self._downloaded_bodies: asyncio.Queue[Tuple[HLSPeer, List[DownloadedBlockPart]]] = asyncio.Queue()  # noqa: E501
        self._executor = get_process_pool_executor()
        
        #{peer_wallet_address, ChainRequestInfo},{peer_wallet_address, ChainRequestInfo}...]
        self.pending_chain_request = {}
        
        
        #number of chains ahead of the last chain we requested. Inclusive
        self.chain_request_num_ahead = 0
        
        self.syncer_initialized = asyncio.Event()
        
        
    def register_peer(self, peer: BasePeer) -> None:
        if self.current_syncing_root_timestamp is None:
            self._idle_peers_in_consensus.put_nowait(peer)
            self.logger.debug("Added peer to consensus queue")
        else:
            if peer.chain_head_root_hashes is not None:
                peer_root_hash_timestamps = dict(peer.chain_head_root_hashes)
                
                try:
                    if(peer_root_hash_timestamps[self.current_syncing_root_timestamp] == self.current_syncing_root_hash):
                        self._idle_peers_in_consensus.put_nowait(peer)
                        self.logger.debug("Added peer to consensus queue")
                    else:
                        self._idle_peers.put_nowait(peer)
                except KeyError:
                    self._idle_peers.put_nowait(peer)
            else:
                self._idle_peers.put_nowait(peer)
            

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
                    while True:
                        asyncio.ensure_future(self.re_queue_timeout_peers())
                        await self.send_chain_requests()
                        
    #        with self.subscribe(self.peer_pool):
    #            while True:
    #                peer_or_finished = await self.wait_first(
    #                    self._sync_requests.get(), self._sync_complete.wait())
    #
    #                # In the case of a fast sync, we return once the sync is completed, and our caller
    #                # must then run the StateDownloader.
    #                if self._sync_complete.is_set():
    #                    return
    #
    #                # Since self._sync_complete is not set, peer_or_finished can only be a HLSPeer
    #                # instance.
    #                asyncio.ensure_future(self.sync(peer_or_finished))

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
                if syncing_info == None:
                    self.current_syncing_root_timestamp, self.current_syncing_root_hash = await self.consensus.get_closest_root_hash_consensus(int(time.time())-FAST_SYNC_CUTOFF_PERIOD)
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
                time.sleep(5)
        return True

    
    async def re_queue_timeout_peers(self):
        while not self._sync_complete.is_set() and self.is_running:
            self.logger.debug("Requeuing peers")
            for peer_wallet_address, chain_request_info in self.pending_chain_request.copy().items():
                if chain_request_info.timestamp_sent < int(time.time()) - REPLY_TIMEOUT:
                    #re-queue peer
                    self.register_peer(self.pending_chain_request[peer_wallet_address].peer)
                    #delete the request
                    del(self.pending_chain_request[peer_wallet_address])
                    
            
            await asyncio.sleep(REPLY_TIMEOUT)
        
    #send a request to a peer asking for the next chain. if it is not found, then it must be older. it cant be newer because of how we initialized sync.
        
    async def send_chain_requests(self):
        while not self._sync_complete.is_set() and self.is_running:
            peer = await self.wait(self._idle_peers_in_consensus.get())
            if peer.is_running:
                self.logger.debug("Found a peer to send chain requests to")
            else:
                self.logger.info("%s disconnected, aborting sync", peer)
                break
            
            
            self.last_window_start = self.last_window_start + self.last_window_length
            window_start = self.last_window_start
            self.last_window_length = NUM_CHAINS_TO_REQUEST
            window_length = self.last_window_length
            
            head_hash_of_last_chain = self.head_hash_of_last_chain
            self.logger.info("Sending chain request to {}, window_start {}, window_length {}".format(peer,window_start,window_length))

            new_chain_request_info = ChainRequestInfo(peer, 
                                                      self.current_syncing_root_timestamp, 
                                                      self.current_syncing_root_hash,
                                                      head_hash_of_last_chain, 
                                                      window_start, 
                                                      window_length, 
                                                      int(time.time()))
            peer.sub_proto.send_get_chains_syncing(new_chain_request_info)
        
    async def sync(self, peer: HLSPeer) -> None:
        if self._syncing:
            self.logger.debug(
                "Got a NewBlock or a new peer, but already syncing so doing nothing")
            return
        elif len(self.peer_pool.peers) < self.min_peers_to_sync:
            self.logger.info(
                "Connected to less peers (%d) than the minimum (%d) required to sync, "
                "doing nothing", len(self.peer_pool.peers), self.min_peers_to_sync)
            return

        self._syncing = True
        try:
            await self._sync(peer)
        except OperationCancelled as e:
            self.logger.info("Sync with %s aborted: %s", peer, e)
        finally:
            self._syncing = False

    async def _sync(self, peer: HLSPeer) -> None:
        head = await self.wait(self.chaindb.coro_get_canonical_head())
        head_td = await self.wait(self.chaindb.coro_get_score(head.hash))
        if peer.head_td <= head_td:
            self.logger.info(
                "Head TD (%d) announced by %s not higher than ours (%d), not syncing",
                peer.head_td, peer, head_td)
            return

        self.logger.info("Starting sync with %s", peer)
        # FIXME: Fetch a batch of headers, in reverse order, starting from our current head, and
        # find the common ancestor between our chain and the peer's.
        start_at = max(0, head.block_number - hls.MAX_HEADERS_FETCH)
        while not self._sync_complete.is_set():
            if not peer.is_running:
                self.logger.info("%s disconnected, aborting sync", peer)
                break

            self.logger.debug("Fetching chain segment starting at #%d", start_at)
            peer.sub_proto.send_get_block_headers(start_at, hls.MAX_HEADERS_FETCH, reverse=False)
            try:
                # Pass the peer's token to self.wait() because we want to abort if either we
                # or the peer terminates.
                headers = await self.wait(
                    self._new_headers.get(),
                    token=peer.cancel_token,
                    timeout=self._reply_timeout)
            except TimeoutError:
                self.logger.warn("Timeout waiting for header batch from %s, aborting sync", peer)
                await peer.cancel()
                break

            self.logger.debug("Got headers segment starting at #%d", start_at)
            # TODO: Process headers for consistency.
            try:
                head_number = await self._process_headers(peer, headers)
            except NoEligiblePeers:
                self.logger.info("No peers have the blocks we want, aborting sync")
                break
            start_at = head_number + 1


    async def _process_headers(self, peer: HLSPeer, headers: List[BlockHeader]) -> int:
        start = time.time()
        target_td = await self._calculate_td(headers)
        await self._download_block_parts(
            target_td,
            [header for header in headers if not _is_body_empty(header)],
            self.request_bodies,
            self._downloaded_bodies,
            _body_key,
            'body')
        self.logger.debug("Got block bodies for chain segment")

        missing_receipts = [header for header in headers if not _is_receipts_empty(header)]
        # Post-Byzantium blocks may have identical receipt roots (e.g. when they have the same
        # number of transactions and all succeed/failed: ropsten blocks 2503212 and 2503284),
        # so we do this to avoid requesting the same receipts multiple times.
        missing_receipts = list(unique(missing_receipts, key=_receipts_key))
        await self._download_block_parts(
            target_td,
            missing_receipts,
            self.request_receipts,
            self._downloaded_receipts,
            _receipts_key,
            'receipt')
        self.logger.debug("Got block receipts for chain segment")

        # FIXME: Get the bodies returned by self._download_block_parts above and use persit_block
        # here.
        for header in headers:
            await self.wait(self.chaindb.coro_persist_header(header))

        head = await self.wait(self.chaindb.coro_get_canonical_head())
        self.logger.info(
            "Imported %d headers in %0.2f seconds, new head: #%d (%s)",
            len(headers),
            time.time() - start,
            head.block_number,
            encode_hex(head.hash)[2:8],
        )
        # Quite often the header batch we receive here includes headers past the peer's reported
        # head (via the NewBlock msg), so we can't compare our head's hash to the peer's in
        # order to see if the sync is completed. Instead we just check that we have the peer's
        # head_hash in our chain.
        try:
            await self.wait(self.chaindb.coro_get_block_header_by_hash(peer.head_hash))
        except HeaderNotFound:
            pass
        else:
            self.logger.info("Fast sync with %s completed", peer)
            self._sync_complete.set()

        return head.block_number

    async def _download_block_parts(
            self,
            target_td: int,
            headers: List[BlockHeader],
            request_func: Callable[[int, List[BlockHeader]], int],
            download_queue: 'asyncio.Queue[Tuple[HLSPeer, List[DownloadedBlockPart]]]',
            key_func: Callable[[BlockHeader], Union[bytes, Tuple[bytes, bytes]]],
            part_name: str) -> 'List[DownloadedBlockPart]':
        """Download block parts for the given headers, using the given request_func.

        Retry timed out parts until we have the parts for all headers.

        Raises NoEligiblePeers if at any moment we have no connected peers that have the blocks
        we want.
        """
        missing = headers.copy()
        # The ETH protocol doesn't guarantee that we'll get all body parts requested, so we need
        # to keep track of the number of pending replies and missing items to decide when to retry
        # them. See request_receipts() for more info.
        pending_replies = request_func(target_td, missing)
        parts: List[DownloadedBlockPart] = []
        while missing:
            if pending_replies == 0:
                pending_replies = request_func(target_td, missing)

            try:
                peer, received = await self.wait(
                    download_queue.get(),
                    timeout=self._reply_timeout)
            except TimeoutError:
                pending_replies = request_func(target_td, missing)
                continue

            received_keys = set([part.unique_key for part in received])

            duplicates = received_keys.intersection(part.unique_key for part in parts)
            unexpected = received_keys.difference(key_func(header) for header in headers)

            parts.extend(received)
            pending_replies -= 1

            if unexpected:
                self.logger.debug("Got unexpected %s from %s: %s", part_name, peer, unexpected)
            if duplicates:
                self.logger.debug("Got duplicate %s from %s: %s", part_name, peer, duplicates)

            missing = [
                header
                for header in missing
                if key_func(header) not in received_keys
            ]

        return parts

    def _request_block_parts(
            self,
            target_td: int,
            headers: List[BlockHeader],
            request_func: Callable[[HLSPeer, List[BlockHeader]], None]) -> int:
        eligible_peers = [
            peer for peer in self.peer_pool.peers if cast(HLSPeer, peer).head_td >= target_td]
        if not eligible_peers:
            raise NoEligiblePeers()
        length = math.ceil(len(headers) / len(eligible_peers))
        batches = list(partition_all(length, headers))
        for peer, batch in zip(eligible_peers, batches):
            request_func(cast(HLSPeer, peer), batch)
        return len(batches)

    def _send_get_block_bodies(self, peer: HLSPeer, headers: List[BlockHeader]) -> None:
        self.logger.debug("Requesting %d block bodies to %s", len(headers), peer)
        peer.sub_proto.send_get_block_bodies([header.hash for header in headers])

    def _send_get_receipts(self, peer: HLSPeer, headers: List[BlockHeader]) -> None:
        self.logger.debug("Requesting %d block receipts to %s", len(headers), peer)
        peer.sub_proto.send_get_receipts([header.hash for header in headers])

    def request_bodies(self, target_td: int, headers: List[BlockHeader]) -> int:
        """Ask our peers for bodies for the given headers.

        See request_receipts() for details of how this is done.
        """
        return self._request_block_parts(target_td, headers, self._send_get_block_bodies)

    def request_receipts(self, target_td: int, headers: List[BlockHeader]) -> int:
        """Ask our peers for receipts for the given headers.

        We partition the given list of headers in batches and request each to one of our connected
        peers. This is done because geth enforces a byte-size cap when replying to a GetReceipts
        msg, and we then need to re-request the items that didn't fit, so by splitting the
        requests across all our peers we reduce the likelyhood of having to make multiple
        serialized requests to ask for missing items (which happens quite frequently in practice).

        Returns the number of requests made.
        """
        return self._request_block_parts(target_td, headers, self._send_get_receipts)

    async def _cleanup(self) -> None:
        # We don't need to cancel() anything, but we yield control just so that the coroutines we
        # run in the background notice the cancel token has been triggered and return.
        await asyncio.sleep(0)

    async def _handle_msg(self, peer: HLSPeer, cmd: protocol.Command,
                          msg: protocol._DecodedMsgType) -> None:
        if isinstance(cmd, hls.BlockHeaders):
            self._handle_block_headers(list(cast(Tuple[BlockHeader], msg)))
        elif isinstance(cmd, hls.BlockBodies):
            await self._handle_block_bodies(peer, list(cast(Tuple[BlockBody], msg)))
        elif isinstance(cmd, hls.Receipts):
            await self._handle_block_receipts(peer, cast(List[List[Receipt]], msg))
        elif isinstance(cmd, hls.NewBlock):
            await self._handle_new_block(peer, cast(Dict[str, Any], msg))
        elif isinstance(cmd, hls.GetBlockHeaders):
            await self._handle_get_block_headers(peer, cast(Dict[str, Any], msg))
        elif isinstance(cmd, hls.GetChainsSyncing):
            await self._handle_get_chains_syncing(peer, cast(Dict[str, Any], msg))
        else:
            #self.logger.debug("Ignoring %s message from %s: msg %r", cmd, peer, msg)
            pass

    def _handle_block_headers(self, headers: List[BlockHeader]) -> None:
        if not headers:
            self.logger.warn("Got an empty BlockHeaders msg")
            return
        self.logger.debug(
            "Got BlockHeaders from %d to %d", headers[0].block_number, headers[-1].block_number)
        self._new_headers.put_nowait(headers)

    async def _handle_new_block(self, peer: HLSPeer, msg: Dict[str, Any]) -> None:
        header = msg['block'][0]
        actual_head = header.parent_hash
        actual_td = msg['total_difficulty'] - header.difficulty
        if actual_td > peer.head_td:
            peer.head_hash = actual_head
            peer.head_td = actual_td
            self._sync_requests.put_nowait(peer)

    async def _handle_block_receipts(self,
                                     peer: HLSPeer,
                                     receipts_by_block: List[List[hls.Receipt]]) -> None:
        self.logger.debug("Got Receipts for %d blocks from %s", len(receipts_by_block), peer)
        loop = asyncio.get_event_loop()
        iterator = map(make_trie_root_and_nodes, receipts_by_block)
        # The map() call above is lazy (it returns an iterator! ;-), so it's only evaluated in
        # the executor when the list() is applied to it.
        receipts_tries = await self.wait(loop.run_in_executor(self._executor, list, iterator))
        downloaded: List[DownloadedBlockPart] = []
        for (receipts, (receipt_root, trie_dict_data)) in zip(receipts_by_block, receipts_tries):
            await self.wait(self.chaindb.coro_persist_trie_data_dict(trie_dict_data))
            downloaded.append(DownloadedBlockPart(receipts, receipt_root))
        self._downloaded_receipts.put_nowait((peer, downloaded))

    async def _handle_block_bodies(self,
                                   peer: HLSPeer,
                                   bodies: List[hls.BlockBody]) -> None:
        self.logger.debug("Got Bodies for %d blocks from %s", len(bodies), peer)
        loop = asyncio.get_event_loop()
        iterator = map(make_trie_root_and_nodes, [body.transactions for body in bodies])
        # The map() call above is lazy (it returns an iterator! ;-), so it's only evaluated in
        # the executor when the list() is applied to it.
        transactions_tries = await self.wait(
            loop.run_in_executor(self._executor, list, iterator))
        downloaded: List[DownloadedBlockPart] = []
        for (body, (tx_root, trie_dict_data)) in zip(bodies, transactions_tries):
            await self.wait(self.chaindb.coro_persist_trie_data_dict(trie_dict_data))
            uncles_hash = await self.wait(self.chaindb.coro_persist_uncles(body.uncles))
            downloaded.append(DownloadedBlockPart(body, (tx_root, uncles_hash)))
        self._downloaded_bodies.put_nowait((peer, downloaded))

    async def _handle_get_block_headers(self,
                                        peer: HLSPeer,
                                        header_request: Dict[str, Any]) -> None:
        self.logger.debug("Peer %s made header request: %s", peer, header_request)
        # TODO: We should *try* to return the requested headers as they *may*
        # have already been synced into our chain database.
        peer.sub_proto.send_block_headers([])
        
    async def _handle_get_chains_syncing(self,
                                        peer: HLSPeer,
                                        chain_request: Dict[str, Any]) -> None:
        self.logger.debug("Peer %s made chains syncing request: %s", peer, chain_request)
        # TODO: We should *try* to return the requested headers as they *may*
        # have already been synced into our chain database.
#        data = {
#            'head_root_hash': chain_request_info.head_root_timestamp,
#            'head_hash_of_last_chain': chain_request_info.head_hash_of_last_chain,
#            'window_start': chain_request_info.window_start,
#            'window_length': chain_request_info.window_length}
        
        next_head_hashes = await self.chain_head_db.coro_get_next_n_head_block_hashes(chain_request['head_hash_of_last_chain'],
                                                                                      chain_request['window_start'], 
                                                                                      chain_request['window_start'],
                                                                                      root_hash = chain_request['head_root_hash'])
        
        for head_hash in next_head_hashes:
            chain_address = await self.chaindb.coro_get_chain_wallet_address_for_block_hash(self.chaindb.db, head_hash)
            whole_chain = await self.coro_get_all_blocks_on_chain(self.chain.get_vm().get_block_class(), chain_address)
            peer.sub_proto.send_chain(whole_chain)


class RegularChainSyncer(FastChainSyncer):
    """
    Sync with the Ethereum network by fetching block headers/bodies and importing them.

    Here, the run() method will execute the sync loop forever, until our CancelToken is triggered.
    """

    def __init__(self,
                 chain: AsyncChain,
                 chaindb: AsyncChainDB,
                 peer_pool: PeerPool,
                 token: CancelToken = None) -> None:
        super().__init__(chaindb, peer_pool, token)
        self.chain = chain

    async def _handle_msg(self, peer: HLSPeer, cmd: protocol.Command,
                          msg: protocol._DecodedMsgType) -> None:
        if isinstance(cmd, hls.BlockHeaders):
            self._handle_block_headers(list(cast(Tuple[BlockHeader], msg)))
        elif isinstance(cmd, hls.BlockBodies):
            await self._handle_block_bodies(peer, list(cast(Tuple[hls.BlockBody], msg)))
        elif isinstance(cmd, hls.NewBlock):
            await self._handle_new_block(peer, cast(Dict[str, Any], msg))
        elif isinstance(cmd, hls.GetBlockHeaders):
            await self._handle_get_block_headers(peer, cast(Dict[str, Any], msg))
        elif isinstance(cmd, hls.GetBlockBodies):
            await self._handle_get_block_bodies(peer, cast(List[Hash32], msg))
        elif isinstance(cmd, hls.GetReceipts):
            await self._handle_get_receipts(peer, cast(List[Hash32], msg))
        elif isinstance(cmd, hls.GetNodeData):
            self._handle_get_node_data(peer, cast(List[Hash32], msg))
        else:
            self.logger.debug("%s msg not handled yet, need to be implemented", cmd)

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


class DownloadedBlockPart(NamedTuple):
    part: Union[hls.BlockBody, List[Receipt]]
    unique_key: Union[bytes, Tuple[bytes, bytes]]


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
    from p2p import ecies
    from evm.chains.ropsten import RopstenChain, ROPSTEN_GENESIS_HEADER
    from evm.db.backends.level import LevelDB
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
    logging.getLogger('p2p.chain.ChainSyncer').setLevel(log_level)

    loop = asyncio.get_event_loop()

    base_db = LevelDB(args.db)
    chaindb = FakeAsyncChainDB(base_db)
    chaindb.persist_header(ROPSTEN_GENESIS_HEADER)
    headerdb = FakeAsyncHeaderDB(base_db)

    privkey = ecies.generate_privkey()
    if args.local_geth:
        peer_pool = LocalGHLSPeerPool(HLSPeer, headerdb, RopstenChain.network_id, privkey)
    else:
        from p2p.peer import HardCodedNodesPeerPool
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
