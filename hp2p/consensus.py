import asyncio
import logging
import math
import operator
import time

from helios.db.chain_head import AsyncChainHeadDB
from helios.protocol.hls import commands
from helios.protocol.hls.sync import get_earliest_required_time_for_min_gas_system, \
    get_sync_stage_for_historical_root_hash_timestamp
from helios.sync.common.constants import ADDITIVE_SYNC_STAGE_ID
from helios.utils.queues import empty_queue
from hp2p.events import NewBlockEvent, StakeFromBootnodeRequest, StakeFromBootnodeResponse, CurrentSyncStageRequest, \
    CurrentSyncStageResponse, CurrentSyncingParametersRequest, CurrentSyncingParametersResponse
from hvm.rlp.consensus import NodeStakingScore

from lahja import Endpoint

from hvm.utils.chain_head_db import round_down_to_nearest_historical_window
from hvm.utils.numeric import (
    effecient_diff,
    stake_weighted_average,
)

from typing import (
    Any,
    Callable,
    Dict,
    List,
    NamedTuple,
    Tuple,
    Union,
    cast,
    Iterable,
    Set,
    Type,
    Optional,
    TYPE_CHECKING
)
from itertools import repeat
from hp2p.protocol import Command
from helios.protocol.common.constants import ROUND_TRIP_TIMEOUT
from helios.exceptions import AlreadyWaiting, NoCandidatePeers
from cytoolz import (
    partition_all,
    unique,
)

from eth_typing import BlockNumber, Hash32, Address
from eth_utils import (
    encode_hex,
    ValidationError,
)

from helios.rlp_templates.hls import (
    BlockBody,
    P2PTransaction,
    BlockNumberKey,
    BlockHashKey,
    P2PBlock)

from hvm.constants import (
    BLANK_ROOT_HASH,
    EMPTY_UNCLE_HASH,
    GENESIS_PARENT_HASH,
    NUMBER_OF_HEAD_HASH_TO_SAVE,
    TIME_BETWEEN_HEAD_HASH_SAVE,
    TIME_BETWEEN_PEER_NODE_HEALTH_CHECK,
    REWARD_BLOCK_CREATION_ATTEMPT_FREQUENCY, MIN_ALLOWED_TIME_BETWEEN_REWARD_BLOCKS,
    REQUIRED_NUMBER_OF_PROOFS_FOR_REWARD_TYPE_2_PROOF, REQUIRED_STAKE_FOR_REWARD_TYPE_2_PROOF,
    COIN_MATURE_TIME_FOR_STAKING)

from helios.chains.coro import AsyncChain
from helios.db.chain import AsyncChainDB
from helios.db.consensus import AsyncConsensusDB
from hvm.db.trie import make_trie_root_and_nodes
from hvm.exceptions import (
    HeaderNotFound,
    NoLocalRootHashTimestamps,
    LocalRootHashNotInConsensus,
    NoChronologicalBlocks,
    NotEnoughDataForHistoricalMinGasPriceCalculation,
    CanonicalHeadNotFound, RewardAmountRoundsToZero)

from hvm.rlp.headers import BlockHeader
from hvm.rlp.receipts import Receipt
from hvm.rlp.transactions import BaseTransaction

from hp2p.constants import (
    MIN_SAFE_PEERS,
    LOCAL_ROOT_HASH_CHECK_MIN_TIME_PERIOD,
    BLOCK_CONFLICT_RESOLUTION_PERIOD,
    CONSENUS_PEER_DISCONNECT_CHECK_PERIOD,
    CONSENSUS_CHECK_READY_TIME_PERIOD,
    ASK_BOOT_NODE_FOR_STAKE_CUTOFF_PERIOD,
    CONSENSUS_SYNC_TIME_PERIOD,
    CONSENSUS_CHECK_MIN_GAS_SYSTEM_READY_TIME_PERIOD,
    CONSENSUS_CHECK_LOCAL_TPC_CAP_PERIOD,
    MIN_GAS_PRICE_SYSTEM_SYNC_WITH_NETWORK_PERIOD,
    MIN_PEERS_TO_CALCULATE_NETWORK_TPC_CAP_AVG,
    ADDITIVE_SYNC_MODE_CUTOFF,
    PEER_STAKE_GONE_STALE_TIME_PERIOD, CONSENSUS_CHECK_CURRENT_SYNC_STAGE_PERIOD, SYNC_WITH_CONSENSUS_LOOP_TIME_PERIOD,
    TIME_OFFSET_TO_FAST_SYNC_TO)

from hp2p import protocol

from helios.protocol.hls.commands import (
    GetChainHeadRootHashTimestamps,
    ChainHeadRootHashTimestamps,
    GetUnorderedBlockHeaderHash,
    UnorderedBlockHeaderHash,
    GetStakeForAddresses,
    StakeForAddresses,
    GetMinGasParameters,
    MinGasParameters,
    GetNodeStakingScore)
from helios.protocol.common.context import ChainContext

from eth_utils import int_to_big_endian

from cancel_token import CancelToken

from hp2p.exceptions import (
    NoEligiblePeers,
    OperationCancelled,
    DatabaseResyncRequired,
    PeerConnectionLost,
    UnknownPeerStake, NotSyncedToAdditiveSyncStartTime)
from hp2p.peer import BasePeer, PeerSubscriber
from helios.protocol.hls.peer import HLSPeerPool

from helios.protocol.hls.peer import HLSPeer
from hp2p.service import BaseService

from hvm.types import Timestamp

from sortedcontainers import SortedDict
from sortedcontainers import SortedList

from helios.protocol.common.datastructures import SyncParameters
if TYPE_CHECKING:
    from helios.nodes.base import Node

class BlockConflictInfo():
    chain_address:Address = None

    def __init__(self, chain_address, block_number):
        self.chain_address = chain_address
        self.block_number = block_number

    def __hash__(self):
        return hash(self.chain_address + int_to_big_endian(self.block_number))

    def __eq__(self, other):
        return self.__hash__() == other.__hash__()
        
class BlockConflictChoice():
    def __init__(self, chain_address, block_number, block_hash):
        self.chain_address = chain_address
        self.block_number = block_number
        self.block_hash = block_hash
        
    def __hash__(self):
        return hash(self.block_hash)
    
    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

class PeerBlockChoice():
    def __init__(self, peer_wallet_address, stake, msg):
        self.peer_wallet_address = peer_wallet_address
        self.stake = stake
        self.msg = msg
        
class PeerRootHashTimestamps():
    def __init__(self, peer_wallet_address, stake, msg):
        self.peer_wallet_address = peer_wallet_address
        self.stake = stake
        self.msg = msg
            
            
                
    
class Consensus(BaseService, PeerSubscriber):
    """
    determine if items have consensus
    get items that have consensus
    """
    msg_queue_maxsize = 500
    subscription_msg_types: Set[Type[Command]] = {
        commands.UnorderedBlockHeaderHash,
        commands.GetUnorderedBlockHeaderHash,
        commands.ChainHeadRootHashTimestamps,
        commands.GetChainHeadRootHashTimestamps,
        commands.StakeForAddresses,
        commands.GetStakeForAddresses,
        commands.GetMinGasParameters,
        commands.MinGasParameters,
        commands.GetNodeStakingScore,
    }


    logger = logging.getLogger("hp2p.consensus.Consensus")
    # We'll only sync if we are connected to at least min_peers_to_sync.
    min_peers_to_sync = 1
    # TODO: Instead of a fixed timeout, we should use a variable one that gets adjusted based on
    # the round-trip times from our download requests.
    _reply_timeout = 60
    _local_root_hash_timestamps = None
    _min_gas_system_ready = False
    #this is {peer_wallet_address: [timestamp_received, network_tpc_cap, stake]}
    _network_tpc_cap_statistics = {}
    _last_check_local_tpc_cap_time = 0
    _local_tpc_cap = 0
    _last_check_if_min_gas_system_ready_time = 0
    _current_sync_stage = 0 #0 means unknown.

    def __init__(self,
                 context: ChainContext,
                 peer_pool: HLSPeerPool,
                 bootstrap_nodes,
                 node,
                 event_bus: Endpoint = None,
                 token: CancelToken = None) -> None:
        super().__init__(token)
        self.node: 'Node' = node
        self.event_bus = event_bus
        self.chains: List[AsyncChain] = context.chains
        self.chaindb = context.chaindb
        self.base_db = context.base_db
        self.consensus_db: AsyncConsensusDB = context.consensus_db
        self.chain_head_db: AsyncChainHeadDB = context.chain_head_db
        self.peer_pool = peer_pool
        self.chain_config = context.chain_config
        self.bootstrap_nodes = bootstrap_nodes
        #[BlockConflictInfo, BlockConflictInfo, ...]
        self.block_conflicts = set()
        #dont forget to include children blocks into weight
        #{peer_wallet_address, [peer_stake, [hls.BlockHashKey]]}
        self.peer_block_choices = {}
        #{chain_wallet_address, {block_number, (block_hash, stake)}}
        self.block_choice_consensus = {}
        #TODO: this might become very slow if someone makes a huge number of conflict blocks. need to worry about that.
        #{chain_wallet_address, {block_number, {block_hash, total_stake}}
        self.block_choice_statistics = {}
        
        #{peer_wallet_address, [peer_stake, [[timestamp, root_hash],[timestamp, root_hash]...]]}
        self.peer_root_hash_timestamps = {}
        #{timestamp, (root_hash, stake)}
        #self.root_hash_timestamps_consensus = {}
        #{timestamp, {root_hash, total_stake}}
        self.root_hash_timestamps_statistics = {}
        
        #PeerBlockChoice, PeerBlockChoice, PeerBlockChoice
        self._new_peer_block_choices = asyncio.Queue()
        #PeerRootHashTimestamps, PeerRootHashTimestamps, PeerRootHashTimestamps
        self._new_peer_chain_head_root_hash_timestamps = asyncio.Queue()

        #NodeStakingScore, NodeStakingScore, ...
        self._new_node_staking_scores = asyncio.Queue()

        self._last_block_choice_consensus_calculation_time = 0
        self._last_check_if_syncing_time = 0
        self._last_check_to_remove_blocks_that_acheived_consensus = 0
        self._last_check_to_remove_disconnected_peer_data = 0
        self._last_check_to_see_if_consensus_ready = 0
        self._last_check_local_root_hash_timestamps = 0
        self._last_check_to_remove_old_local_root_hash_timestamps_from_peer_statistics = 0
        
        #{wallet_address:stake...}
        self.peer_stake_from_bootstrap_node = {}
        
        self.num_peers_contributing_to_consensus = 0

        
        self.coro_is_ready = asyncio.Event()
        self.coro_root_hash_statistics_ready = asyncio.Event()
        self.coro_min_gas_system_ready = asyncio.Event()

        self._write_to_root_hash_timestamps_statistics = asyncio.Lock()
     
    '''
    Properties and utils
    '''


    #TODO. check to make sure the peers also have stake that is not equal to None
    @property
    def has_enough_peers(self):
        if len(self.peer_pool.connected_nodes) >= MIN_SAFE_PEERS:
            self.logger.debug("Has enough peers. connected peers: {}".format(self.peer_pool.connected_nodes.keys()))
        else:
            self.logger.debug("doesnt have enough peers. connected peers: {}".format(self.peer_pool.connected_nodes.keys()))
            pass
        return len(self.peer_pool.connected_nodes) >= MIN_SAFE_PEERS
    
    @property
    def is_bootnode(self) -> bool:
        return self.chain_config.node_type == 4

    @property
    def is_network_startup_node(self) -> bool:
        return self.chain_config.network_startup_node

    @property
    def has_enough_consensus_participants(self):
        if len(self.peer_root_hash_timestamps) >= MIN_SAFE_PEERS or self.is_network_startup_node:
            self.logger.debug("has_enough_consensus_participants. wallets involved: {}".format(self.peer_root_hash_timestamps.keys()))
        else:
            self.logger.debug("doesnt has_enough_consensus_participants. wallets involved: {}".format(self.peer_root_hash_timestamps.keys()))
            pass

        #we don't want to count any peers who we don't have stake for.
        return len(self.peer_root_hash_timestamps) >= MIN_SAFE_PEERS or self.is_network_startup_node
    

    @property
    async def current_sync_stage(self):
        '''
        Returns the current sync stage id
        '''

        if self._last_check_if_syncing_time < (int(time.time()) - SYNC_WITH_CONSENSUS_LOOP_TIME_PERIOD):
            if not self.coro_is_ready.is_set():
                self._current_sync_stage = 0
            else:
                try:
                    sync_params = await self.get_blockchain_sync_parameters()
                except NoEligiblePeers:
                    self._current_sync_stage = 0
                else:
                    if sync_params is None:
                        self._current_sync_stage = 4
                    else:
                        sync_stage = sync_params.sync_stage
                        self._current_sync_stage = sync_stage

            self._last_check_if_syncing_time = int(time.time())

        self.logger.debug("SYNC STAGE {}".format(self._current_sync_stage))
        return self._current_sync_stage

    @current_sync_stage.setter
    def current_sync_stage(self, sync_stage):
        self._current_sync_stage = sync_stage
        self._last_check_if_syncing_time = int(time.time())

    #    @property
#    def min_gas_system_ready(self):
#        '''
#        checks to see if the throttling system that controls minimum required gas is ready. 
#        if it is not ready we cannot accept new blocks unless from another node.
#        '''
#        if self._min_gas_system_ready is False or self._last_check_if_min_gas_system_ready_time < (int(time.time()) - CONSENSUS_CHECK_MIN_GAS_SYSTEM_READY_TIME_PERIOD):
#            self._min_gas_system_ready = not self.chaindb.min_gas_system_initialization_required()
#            self._last_check_if_min_gas_system_ready_time = int(time.time())
#        
#        return self._min_gas_system_ready
        
    @property
    async def local_tpc_cap(self):
        '''
        the maximum number of blocks that can be imported with a single transaction in 1 centisecond.
        not exactly the tpc, but something consistent to base throttling off of.
        '''
        chain = self.node.get_chain()
        if self._local_tpc_cap == 0 or self._last_check_local_tpc_cap_time < (int(time.time()) - CONSENSUS_CHECK_LOCAL_TPC_CAP_PERIOD):
            self._local_tpc_cap = await chain.coro_get_local_tpc_cap()
            self._last_check_local_tpc_cap_time = int(time.time())
        
        return self._local_tpc_cap

    async def needs_stake_from_bootnode(self, peer):
        time_for_stake_maturity = int(time.time()) - COIN_MATURE_TIME_FOR_STAKING
        latest_timestamp = self.chain_head_db.get_latest_timestamp()

        if (latest_timestamp < time_for_stake_maturity or await peer.stake == None):
            return True
        return False

    async def get_accurate_stake_for_this_node(self):
        time_for_stake_maturity = int(time.time()) - COIN_MATURE_TIME_FOR_STAKING
        latest_timestamp = self.chain_head_db.get_latest_timestamp()

        if latest_timestamp < time_for_stake_maturity and not self.chain_config.network_startup_node:
            try:
                return self.peer_stake_from_bootstrap_node[self.chain_config.node_wallet_address]
            except KeyError:
                raise UnknownPeerStake()
        else:
            return await self.chaindb.coro_get_mature_stake(wallet_address=self.chain_config.node_wallet_address)

    async def get_accurate_stake(self, peer: HLSPeer):
        if self.chain_config.network_startup_node:
            to_return = await peer.stake
            if to_return == None:
                return 0
            else:
                return to_return
        else:
            if await self.needs_stake_from_bootnode(peer):
                try:
                    return self.peer_stake_from_bootstrap_node[peer.wallet_address]
                except KeyError:
                    raise UnknownPeerStake()
        return await peer.stake

 
    def determine_stake_winner(self, item_stakes_dict_or_list):
        '''
        takes in a dictionary where the keys are the items which are voted on, and the values are the stake.
        returns a tuple containing the highest stake item, and its stake
        '''
        if isinstance(item_stakes_dict_or_list, dict):
            max_stake = 0
            max_item = None
            for item, stake in item_stakes_dict_or_list.items():
                if max_item is None:
                    max_stake = stake
                    max_item = item
                else:
                    if stake > max_stake:
                        max_stake = stake
                        max_item = item
                    elif stake == max_stake:
                        if max_item == None:
                            max_stake = stake
                            max_item = item
                        else:
                            if item > max_item:
                                max_stake = stake
                                max_item = item
            assert(max_item is not None), item_stakes_dict_or_list
            return (max_item, max_stake)
        elif isinstance(item_stakes_dict_or_list, list):
            max_stake = 0
            max_item = None
            for item_stake in item_stakes_dict_or_list:
                item = item_stake[0]
                stake = item_stake[1]
                if max_item is None:
                    max_stake = stake
                    max_item = item
                else:
                    if stake > max_stake:
                        max_stake = stake
                        max_item = item
                    elif stake == max_stake:
                        if max_item == None:
                            max_stake = stake
                            max_item = item
                        else:
                            if item > max_item:
                                max_stake = stake
                                max_item = item
            assert(max_item is not None)
            return (max_item, max_stake)
    
    def calc_stake_difference(self, prev_block_hash_keys, new_block_hash_keys):
        '''
        effeciently determines the difference between the new data and the old data.
        Returns stake_subtract, which is items there previously that are no longer there
        and stake add, which are new items that werent there previously.
        '''
        stake_subtract = effecient_diff(new_block_hash_keys, prev_block_hash_keys)
        stake_add = effecient_diff(prev_block_hash_keys, new_block_hash_keys)
        return stake_subtract, stake_add
        

    def delta_block_choice_statistics(self, chain_wallet_address, block_number, block_hash, delta):
        '''
        adds or subtracts stake for a given block choice. Stores the new statistics in local statistics files
        '''
        try:
            self.block_choice_statistics[chain_wallet_address][block_number][block_hash] += delta
        except KeyError:
            if chain_wallet_address in self.block_choice_statistics:
                if block_number in self.block_choice_statistics[chain_wallet_address]:
                    self.block_choice_statistics[chain_wallet_address][block_number][block_hash] = delta
                else:
                    self.block_choice_statistics[chain_wallet_address][block_number] = {block_hash: delta}
            else:
                self.block_choice_statistics[chain_wallet_address] = {block_number: {block_hash: delta}}
        
        return self.block_choice_statistics
    

    
    def delta_root_hash_timestamp_statistics(self, timestamp, root_hash, delta):
        '''
        adds or subtracts stake for a given root hash. Stores the new statistics in local statistics files
        '''
        try:
            self.root_hash_timestamps_statistics[timestamp][root_hash] += delta
        except KeyError:
            if timestamp in self.root_hash_timestamps_statistics:
                self.root_hash_timestamps_statistics[timestamp][root_hash] = delta
            else:
                self.root_hash_timestamps_statistics[timestamp] = {root_hash: delta}
    
    def get_winner_stake_binary_compare(self, bin_item_1, stake_1, bin_item_2, stake_2):
        '''
        Returns the item of largest stake, it there is a tie, it compares the binary items and returns the greatest
        '''
        if stake_1 > stake_2:
            #our stake is greater, lets stick with our choice.
            return bin_item_1
        elif stake_1 < stake_2:
            #peers have more stake. lets go with their choice.
            return bin_item_2
        else:
            #we have a tie. return the greater binary hash
            if bin_item_1 > bin_item_2:
                return bin_item_1
            else:
                return bin_item_2
                
            
    '''
    Standard service functions
    '''
    def register_peer(self, peer: BasePeer) -> None:
        #self.peer_root_hash_timestamps[peer.wallet_address] = [new_peer_stake, new_root_hash_timestamps]
        pass

    ###############
    ## Loopers
    ###############
    async def _handle_msg_loop(self) -> None:
        while self.is_running:
            try:
                peer, cmd, msg = await self.wait(self.msg_queue.get())
            except OperationCancelled:
                break

            # Our handle_msg() method runs cpu-intensive tasks in sub-processes so that the main
            # loop can keep processing msgs, and that's why we use ensure_future() instead of
            # awaiting for it to finish here.
            #self.logger.debug("received cmd, msg {}, {}".format(cmd, msg))
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


    async def _sync_min_gas_price_system_loop(self):
        while self.is_running:
            try:
                #await self.sync_min_gas_price_system()
                await self.wait(self.sync_min_gas_price_system(), token = self.cancel_token)
            except OperationCancelled:
                break
            except Exception as e:
                self.logger.exception("Unexpected error when syncing minimum gas system. Error: {}".format(e))

            await asyncio.sleep(MIN_GAS_PRICE_SYSTEM_SYNC_WITH_NETWORK_PERIOD)

    @property
    async def peers_with_known_stake(self) -> List:
        peers_to_return = []
        for peer in self.peer_pool.peers:
            try:
                stake = await self.get_accurate_stake(peer)
                peers_to_return.append(peer)
            except UnknownPeerStake:
                # If we don't know their stake yet. Don't add it to the statistics.
                pass
        return peers_to_return


    async def _run(self) -> None:
        self.logger.info("Starting consensus service")
        if self.is_network_startup_node:
            self.logger.debug('re-initializing min gas system')
            self.node.get_chain().re_initialize_historical_minimum_gas_price_at_genesis()

        self.run_daemon_task(self._handle_msg_loop())

        with self.subscribe(self.peer_pool):
            self.run_daemon_task(self.get_missing_stake_from_bootnode_loop())
            self.run_daemon_task(self._sync_min_gas_price_system_loop())
            self.run_daemon_task(self.peer_node_health_syncer_loop())
            self.run_daemon_task(self.staking_reward_loop())
            self.run_daemon_task(self.receive_peer_block_choices_loop())
            self.run_daemon_task(self.receive_peer_chain_head_root_hash_timestamps_loop())
            self.run_daemon_task(self.send_get_consensus_statistics_loop())
            if self.event_bus is not None:
                self.run_daemon_task(self.handle_event_bus_events())

            while self.is_operational:
                #self.logger.debug("Our historical root hashes = {}".format(self.chain_head_db.get_historical_root_hashes()))
                try:
                    self.logger.debug("This node's stake = {}".format(await self.get_accurate_stake_for_this_node()))
                except UnknownPeerStake:
                    self.logger.debug("This node's stake = {}".format("unknown"))

                self.logger.debug("Number of connected peers = {}".format(len(self.peer_pool)))
                wallet_stake = [(peer.wallet_address, await peer.stake) for peer in self.peer_pool.peers]
                self.logger.debug("{}".format(wallet_stake))
                #first lets ask the bootnode for the stake of any peers that we dont have the blockchain for
                #this takes care of determining stake of our peers while we are still syncing our blockchain database
                #self.logger.debug("waiting for get missing stake from bootnode")
                #await self.wait(self.get_missing_stake_from_bootnode())
                #send sync messages, doesnt need to be async
                #self.send_sync_get_messages()
                #it will re-loop every time it gets a new response from a single peer. this ensures that the statistics are always as up to date as possible

                self.logger.debug("done syncing consensus. These are the statistics for block_choices: {}".format(
                                    self.block_choice_statistics))
                
                sorted_root_hash_timestamps_statistics = list(SortedDict(self.root_hash_timestamps_statistics).items())
                self.logger.debug("done syncing consensus. These are the statistics for root_hashes: {}".format(
                                   sorted_root_hash_timestamps_statistics[-10:]))
                #blocks_to_change = await self.get_correct_block_conflict_choice_where_we_differ_from_consensus()
                #self.logger.debug('get_correct_block_conflict_hashes_where_we_differ_from_consensus = {}'.format(blocks_to_change))
#                if blocks_to_change is not None:
#                    self.logger.debug('get_peers_who_have_conflict_block {}'.format(self.get_peers_who_have_conflict_block(blocks_to_change[0])))
#                 test_1 = self.chaindb.load_historical_network_tpc_capability()
#                 test_2 = self.chaindb.load_historical_minimum_gas_price()
#                 test_3 = self.chaindb.load_historical_tx_per_centisecond()
#                 self.logger.debug("net_tpc_cap = {}".format(test_1))
#                 self.logger.debug("min_gas_price = {}".format(test_2))
#                 self.logger.debug("tpc = {}".format(test_3))
                
                #here we shouldnt pause because if it returned early than thats because we got some data from peers. we want to process data asap.
                #We removed this because we calculate consensus on the fly now.
                #self.populate_peer_consensus()
                #TODO. when a peer disconnects, make sure we delete their vote.
                
                #todo: re-enable these Actually need to re-enable
                #todo: these will cause statistics problems because the statistics subtracts previous stake then adds new stake.
                #if the previous stake was deleted, it will just add the new stake and double the stake.
                #self.remove_data_for_old_root_hash_timestamps()
                #self.remove_data_for_disconnected_peers()
                #self.remove_data_for_blocks_that_achieved_consensus()
                
                #this is run after populate consensus. so if there are enough peers who we have root hashes for, then they will be included in consensus.
                self.check_if_ready()
                
                #yeild control to other coroutines after each loop
                await asyncio.sleep(CONSENSUS_SYNC_TIME_PERIOD)
            



    async def _cleanup(self) -> None:
        # We don't need to cancel() anything, but we yield control just so that the coroutines we
        # run in the background notice the cancel token has been triggered and return.
        await asyncio.sleep(0)
        
    def check_if_ready(self):
        if self.has_enough_consensus_participants and self.has_enough_peers:
            self.coro_is_ready.set()
            self.logger.debug("Coro_is_ready.set()")
        else:
            self.coro_is_ready.clear()
            self.logger.debug("Coro_is_ready.clear()")


    ###
    ###Core functionality
    ###
    async def staking_reward_loop(self) -> None:
        # TODO: Look at all the peers we are connected to, check the score that we have for them, and require that we get
        # responses from those node. If we have a high score for them, they should have a high score for us.
        await self.coro_is_ready.wait()

        await asyncio.sleep(5)

        while self.is_operational:


            self.logger.debug("Running staking_reward_loop")
            if await self.current_sync_stage != 4:
                self.logger.debug("Can only import new reward blocks when our database is completely up to date and sync stage is 4")
            else:
                #We don't want the first block on the chain to be a reward block, because it is just a waste and will be 0 reward.
                #So lets make sure our canonical head is greater than 0
                try:
                    canonical_head_hash = await self.chaindb.coro_get_canonical_head_hash(self.chain_config.node_wallet_address)
                except CanonicalHeadNotFound:
                    self.logger.debug("There are no blocks on the chain for this node's wallet address. Skipping reward block loop until we have at least 1 block.")
                else:
                    latest_reward_block_number = await self.chaindb.coro_get_latest_reward_block_number(self.chain_config.node_wallet_address)
                    latest_reward_block_header = await self.chaindb.coro_get_canonical_block_header_by_number(latest_reward_block_number, self.chain_config.node_wallet_address)
                    latest_reward_block_timestamp = latest_reward_block_header.timestamp

                    if (int(time.time()) - latest_reward_block_timestamp) > MIN_ALLOWED_TIME_BETWEEN_REWARD_BLOCKS:
                        #clear the queue in case there are any old requests
                        empty_queue(self._new_node_staking_scores)
                        #send out all of the requests
                        num_requests_sent = 0
                        for peer in self.peer_pool.peers:
                            self.run_task(self._get_node_staking_score_from_peer(peer, latest_reward_block_number))
                            num_requests_sent += 1

                        await asyncio.sleep(ROUND_TRIP_TIMEOUT)

                        #here lets have a timeout. But lets make it generous to account for uncertainties in block
                        #import times with the chain syncer.
                        try:
                            await self.wait(self.receive_node_staking_scores(num_requests_sent = num_requests_sent),
                                      token=self.cancel_token,
                                      timeout = ROUND_TRIP_TIMEOUT*10)
                        except TimeoutError:
                            self.logger.warning("Attempted to create reward block, but not enough peers replied with a score. Will re-attempt later.")
                            pass


            await asyncio.sleep(REWARD_BLOCK_CREATION_ATTEMPT_FREQUENCY)

    async def receive_node_staking_scores(self, num_requests_sent: int) -> None:
        # receive all of the requests
        while True:

            q_size = self._new_node_staking_scores.qsize()

            # make sure we got enough responses
            required_responses = max((0.51 * num_requests_sent), REQUIRED_NUMBER_OF_PROOFS_FOR_REWARD_TYPE_2_PROOF)
            self.logger.debug("waiting for node_staking_scores to fill queue. Queue size = {}, required responses = {}".format(q_size, required_responses))
            if q_size >= required_responses:
                self.logger.debug("got enough node_staking_scores responses")
                peer_node_staking_scores = [self._new_node_staking_scores.get_nowait() for _ in range(q_size)]
                # make sure we have enough stake
                total_stake = 0
                for node_staking_score in peer_node_staking_scores:
                    total_stake += await self.chaindb.coro_get_mature_stake(node_staking_score.sender)

                self.logger.debug("total stake = {}, required stake = {}".format(total_stake, REQUIRED_STAKE_FOR_REWARD_TYPE_2_PROOF))
                if total_stake > REQUIRED_STAKE_FOR_REWARD_TYPE_2_PROOF:
                    await self.process_reward_block(peer_node_staking_scores)

            await asyncio.sleep(ROUND_TRIP_TIMEOUT)

    async def process_reward_block(self, node_staking_score_list: List[NodeStakingScore]) -> None:
        self.logger.debug("Processing reward block")
        try:
            chain = self.node.get_new_private_chain()
            new_block = await chain.coro_import_current_queue_block_with_reward(node_staking_score_list)
            #self.logger.debug("sending new block event with reward amounts = {}, {}".format(new_block.reward_bundle.reward_type_1.amount, new_block.reward_bundle.reward_type_2.amount))
            self.event_bus.broadcast(
                NewBlockEvent(block = cast(P2PBlock, new_block), only_propogate_to_network=True)
            )
        except RewardAmountRoundsToZero:
            self.logger.warning("Tried to import a reward block, but the reward amounts rounded to 0. More time needs to pass before importing a reward block.")
        except Exception as e:
            self.logger.error("Error when importing reward block: {}".format(e))


    async def _get_node_staking_score_from_peer(self, peer: HLSPeer, since_block: BlockNumber):
        self.logger.debug("Asing peer for our node staking score. peer = {}.".format(encode_hex(peer.wallet_address)))
        while True:
            try:
                node_staking_score = await peer.requests.get_node_staking_score(since_block=since_block, consensus_db = self.consensus_db)

                if node_staking_score is not None:
                    self.logger.debug("Received node staking score from peer {}".format(encode_hex(peer.wallet_address)))
                    self._new_node_staking_scores.put_nowait(node_staking_score)
                else:
                    self.logger.debug("get_node_staking_score_from_peer didn't send anything back")
                break
            except PeerConnectionLost:
                self.logger.debug('get_node_staking_score_from_peer PeerConnectionLost error')
                break
            except TimeoutError:
                self.logger.debug('get_node_staking_score_from_peer TimeoutError error')
                break
            except ValidationError as e:
                raise e
            except AlreadyWaiting:
                # we already have a pending request to this peer. Pause and then try again
                await asyncio.sleep(ROUND_TRIP_TIMEOUT)
                continue
            except Exception as e:
                self.logger.error("Error when receiving staking score from peer. {}".format(e))
                break


    async def peer_node_health_syncer_loop(self) -> None:
        '''
        This function will continue to contact peers every TIME_BETWEEN_PEER_NODE_HEALTH_CHECK and ask them for a
        relatively new block. It will monitor the response and save the statistics to the database.
        It provides a measure of how well the node is doing in terms of adding to the health of the network
        :return:
        '''
        await self.coro_is_ready.wait()
        await asyncio.sleep(5)
        chain = self.node.get_chain()
        self.logger.debug("Running peer node health syncer")
        while self.is_operational:
            #make sure we havent don't a request within the past TIME_BETWEEN_PEER_NODE_HEALTH_CHECK
            #here we need to account for the fact that the latest a health check can be saved is ROUND_TRIP_TIMEOUT from
            #when the request was made
            timestamp_rounded = int(int((time.time()+ROUND_TRIP_TIMEOUT) / (TIME_BETWEEN_PEER_NODE_HEALTH_CHECK)) * (TIME_BETWEEN_PEER_NODE_HEALTH_CHECK))
            time_of_last_request = self.consensus_db.get_timestamp_of_last_health_request()

            if timestamp_rounded >= time_of_last_request + TIME_BETWEEN_PEER_NODE_HEALTH_CHECK:
                # choose random new block to ask all peers for
                try:
                    newish_block_hash = await chain.coro_get_new_block_hash_to_test_peer_node_health()
                except NoChronologicalBlocks:
                    self.logger.debug("Skipping this round of peer node health checks because we have no blocks to ask for")
                    await asyncio.sleep(10)
                else:
                    if len(self.peer_pool) > 0:
                        #make sure we have some peers to ask
                        for peer in self.peer_pool.peers:
                            #this will sync will all peers at the same time
                            self.run_task(self._sync_peer_node_health(peer, newish_block_hash))

                        await asyncio.sleep(TIME_BETWEEN_PEER_NODE_HEALTH_CHECK)
                        continue
                    else:
                        #we didn't have any connected nodes. This will occur if we just started. Lets wait a few seconds and try again.
                        self.logger.debug("No nodes to send peer node health request to. Will retry in a few seconds")
                        await asyncio.sleep(10)
                        continue
            else:
                self.logger.debug("Already did a peer node health check recently. Skipping this health check period.")
                await asyncio.sleep(10)



    async def _sync_peer_node_health(self, peer: HLSPeer, block_hash: Hash32) -> None:
        '''
        This will try to sync with an individual peer. If their is already a request pending, it will retry until
        the request goes through or fails.
        :param peer:
        :param block_hash:
        :return:
        '''
        self.logger.debug("Starting syncing peer node health with peer {}.".format(encode_hex(peer.wallet_address)))
        while True:
            try:
                received_blocks = await peer.requests.get_blocks(
                    block_hashes=(block_hash,),
                )

                if len(received_blocks) > 0:
                    self.consensus_db.save_health_request(peer.wallet_address,
                                                          response_time_in_micros = peer.requests.get_blocks.tracker.latest_response_time*1000*1000)
                else:
                    self.logger.debug('Peer health request didnt send back any blocks')
                    self.consensus_db.save_health_request(peer.wallet_address)
                break
            except PeerConnectionLost:
                self.logger.debug('Peer health request PeerConnectionLost error')
                self.consensus_db.save_health_request(peer.wallet_address)
                break
            except TimeoutError:
                self.logger.debug('Peer health request TimeoutError error')
                self.consensus_db.save_health_request(peer.wallet_address)
                break
            except ValidationError as e:
                raise e
            except AlreadyWaiting:
                #we already have a pending request to this peer. Pause and then try again
                await asyncio.sleep(ROUND_TRIP_TIMEOUT)
                continue
            except Exception as e:
                raise e

        self.logger.debug("Finished syncing peer node health with peer {}.".format(encode_hex(peer.wallet_address)))
        self.logger.debug(self.consensus_db.get_current_peer_node_health(peer.wallet_address))


    async def get_missing_stake_from_bootnode_loop(self):
        self.logger.debug("Running get_missing_stake_from_bootnode_loop")
        while self.is_operational:
            await self._get_missing_stake_from_bootnode()
            await asyncio.sleep(PEER_STAKE_GONE_STALE_TIME_PERIOD)

    async def send_get_consensus_statistics_loop(self) -> None:
        self.logger.debug("Running send_get_consensus_statistics_loop")
        while self.is_operational:
            #sync peer block choices and chain head root hashes
            self.logger.info("Sending syncing consensus messages to all connected peers")

            await self.send_block_conflict_messages(self.block_conflicts)

            for peer in await self.peers_with_known_stake:
                self.logger.debug("Asking peer {} for chain head root hash timestamps".format(peer))
                peer.sub_proto.send_get_chain_head_root_hash_timestamps(0)

            await asyncio.sleep(CONSENSUS_SYNC_TIME_PERIOD)
        
    async def send_block_conflict_messages(self, block_conflicts: Iterable[BlockConflictInfo]) -> None:
        
        self.logger.debug("Sending out messages to all peers asking for block conflict choices.")
        # if not isinstance(block_conflicts, list) and not isinstance(block_conflicts, set):
        #     block_conflicts = {block_conflicts}

        block_number_keys = []
        for conflict in block_conflicts:
            block_number_keys.append(BlockNumberKey(wallet_address = conflict.chain_address, block_number = conflict.block_number))

        for peer in await self.peers_with_known_stake:
            self.logger.debug("Asking peer {} for block conflict choices".format(peer))
            if len(block_number_keys) > 0:
                peer.sub_proto.send_get_unordered_block_header_hash(block_number_keys)


    async def add_peer_block_conflict_choice(self, peer: HLSPeer, block_number: BlockNumber, block_hash: Hash32) -> None:
        peer_wallet_address = peer.wallet_address
        block_hash_key = BlockHashKey(wallet_address = peer_wallet_address,
                                      block_number = block_number,
                                      block_hash = block_hash)
        try:
            stake = await self.get_accurate_stake(peer)

            new_peer_block_choice = PeerBlockChoice(peer_wallet_address, stake, block_hash_key)
            self._new_peer_block_choices.put_nowait(new_peer_block_choice)
        except UnknownPeerStake:
            #If we don't know their stake yet. Don't add it to the statistics.
            pass

    async def receive_peer_block_choices_loop(self):
        self.logger.debug("Starting receive_peer_block_choices_loop")
        while self.is_operational:
            block_choices = await self.wait(self._new_peer_block_choices.get(), token=self.cancel_token)

            peer_wallet_address = block_choices.peer_wallet_address
            new_peer_stake = block_choices.stake
            new_block_hash_keys = block_choices.msg

            # lets only update diff for this peer to reduce overhead.
            if peer_wallet_address in self.peer_block_choices:
                previous_peer_stake = self.peer_block_choices[peer_wallet_address][0]
                previous_block_hash_keys = self.peer_block_choices[peer_wallet_address][1]

                # lets just find the difference this way. should be more effectient. hopefully.
                stake_sub, stake_add = self.calc_stake_difference(previous_block_hash_keys, new_block_hash_keys)
                # first we subtract the previous stake
                for previous_block_hash_key in stake_sub:
                    self.delta_block_choice_statistics(previous_block_hash_key.wallet_address,
                                                       previous_block_hash_key.block_number,
                                                       previous_block_hash_key.block_hash,
                                                       -1 * previous_peer_stake)

                # now add the new stake with new choices
                for new_block_hash_key in stake_add:
                    self.delta_block_choice_statistics(new_block_hash_key.wallet_address,
                                                       new_block_hash_key.block_number,
                                                       new_block_hash_key.block_hash,
                                                       new_peer_stake)


            else:
                # this is the first message from them, we don't have any previous choices, so lets just add the new stake
                for new_block_hash_key in new_block_hash_keys:
                    self.delta_block_choice_statistics(new_block_hash_key.wallet_address,
                                                       new_block_hash_key.block_number,
                                                       new_block_hash_key.block_hash,
                                                       new_peer_stake)

            # finally, update the peer block choices
            self.peer_block_choices[peer_wallet_address] = [new_peer_stake, new_block_hash_keys]

    def get_chain_head_root_hash_for_peer(self, peer_wallet_address: Address, timestamp: Timestamp) -> Optional[Hash32]:

        try:
            root_hash_timestamps = self.peer_root_hash_timestamps[peer_wallet_address][1]
        except KeyError:
            return None

        root_hash_timestamps_dict = dict(root_hash_timestamps)
        #assert(len(root_hash_timestamps_dict) == len(root_hash_timestamps))

        try:
            return root_hash_timestamps_dict[timestamp]
        except KeyError:
            return None


    async def receive_peer_chain_head_root_hash_timestamps_loop(self):
        self.logger.debug("Starting receive_peer_chain_head_root_hash_timestamps_loop")
        while self.is_operational:
            root_hash_timestamp_item = await self.wait(self._new_peer_chain_head_root_hash_timestamps.get(), token=self.cancel_token)
            self.logger.debug("receive_peer_chain_head_root_hash_timestamps_loop new loop")
            peer_wallet_address = root_hash_timestamp_item.peer_wallet_address
            new_peer_stake = root_hash_timestamp_item.stake
            new_root_hash_timestamps = root_hash_timestamp_item.msg
            # self.logger.debug("dealing with new root_hash_timestamps {}".format(new_root_hash_timestamps))

            # first we check to see if we have an entry for this peer:
            if peer_wallet_address in self.peer_root_hash_timestamps:

                previous_peer_stake = self.peer_root_hash_timestamps[peer_wallet_address][0]
                previous_root_hash_timestamps = self.peer_root_hash_timestamps[peer_wallet_address][1]

                # We have to handle 2 cases, 1) Their root hash choices change. 2) Thier stake changes.
                # Lets find the difference between previous and new choices and stake
                previous_bundles = list(zip(repeat(previous_peer_stake, len(previous_root_hash_timestamps)), previous_root_hash_timestamps))
                new_bundles = list(zip(repeat(previous_peer_stake, len(new_root_hash_timestamps)), new_root_hash_timestamps))

                bundle_subs, bundle_adds = self.calc_stake_difference(previous_bundles,
                                                                  new_bundles)
                # if len(stake_sub) > 0 or len(stake_add) > 0:
                #     print('AAAAAAAAAAAAAAA')
                #     print(self.peer_root_hash_timestamps[peer_wallet_address])
                #     print(new_peer_stake, new_root_hash_timestamps)
                # self.logger.debug("subtracting stake {} from timestamps {}".format(previous_peer_stake, [x[0] for x in stake_sub]))
                # self.logger.debug("adding stake {} from timestamps {}".format(new_peer_stake, [x[0] for x in stake_add]))
                # first we subtract the previous stake

                # print("AAAAAAAAAAAAAAAAA")
                # print(bundle_subs[-5:])
                # print(bundle_adds[-5:])
                async with self._write_to_root_hash_timestamps_statistics:
                    for bundle in bundle_subs:
                        stake_sub = bundle[0]
                        previous_root_hash_timestamp = bundle[1]
                        self.delta_root_hash_timestamp_statistics(
                            previous_root_hash_timestamp[0],  # timestamp
                            previous_root_hash_timestamp[1],  # root_hash
                            -1 * stake_sub)

                    # now add the new stake with new choices
                    for bundle in bundle_adds:
                        stake_add = bundle[0]
                        previous_root_hash_timestamp = bundle[1]
                        self.delta_root_hash_timestamp_statistics(
                            previous_root_hash_timestamp[0],  # timestamp
                            previous_root_hash_timestamp[1],  # root_hash
                            stake_add)


            else:
                # now add the new stake with new choices
                async with self._write_to_root_hash_timestamps_statistics:
                    for new_root_hash_timestamp in new_root_hash_timestamps:
                        self.delta_root_hash_timestamp_statistics(
                            new_root_hash_timestamp[0],  # timestamp
                            new_root_hash_timestamp[1],  # root_hash
                            new_peer_stake)
            # finally, update the peer block choices
            self.peer_root_hash_timestamps[peer_wallet_address] = [new_peer_stake, new_root_hash_timestamps]



    async def calculate_average_network_tpc_cap(self):
        num_candidates = 0
        all_candidate_item_stake = []
        if len(self._network_tpc_cap_statistics) >= MIN_PEERS_TO_CALCULATE_NETWORK_TPC_CAP_AVG:

            for wallet_address, timestamp_max_tpc_cap_stake in self._network_tpc_cap_statistics.copy().items():
                if timestamp_max_tpc_cap_stake[0] >= int(time.time())-5*60:
                    all_candidate_item_stake.append([timestamp_max_tpc_cap_stake[1], timestamp_max_tpc_cap_stake[2]])
                    num_candidates +=1
                else:
                    del(self._network_tpc_cap_statistics[wallet_address])

        if num_candidates >= MIN_PEERS_TO_CALCULATE_NETWORK_TPC_CAP_AVG:
            #add in our local tpc and stake
            local_tpc_cap = await self.local_tpc_cap

            local_stake = await self.chaindb.coro_get_mature_stake(self.chain_config.node_wallet_address)


            
            if local_stake != 0:
                all_candidate_item_stake.append([local_tpc_cap, local_stake])
            
            if len(all_candidate_item_stake) == 0:
                return None

            try:
                average_network_tpc_cap = int(stake_weighted_average(all_candidate_item_stake))
                return average_network_tpc_cap
            except ZeroDivisionError:
                self.logger.debug("Divided by zero when calculating average network tpc cap. all_candidate_item_stake = {}".format(all_candidate_item_stake))
                return None
        else:
            return None




    async def sync_min_gas_price_system(self):
        '''
        Makes sure our system for keeping track of minimum allowed gas price is in sync with the network
        This is used to throttle the transaction rate when it reaches the limit that the network can handle.
        '''
        if self.chaindb.min_gas_system_initialization_required():
            self.coro_min_gas_system_ready.clear()
        else:
            self.coro_min_gas_system_ready.set()

        chain = self.node.get_chain()
        if self.coro_min_gas_system_ready.is_set():
            self.logger.debug("sync_min_gas_price_system, min_gas_system_ready = True")
            average_network_tpc_cap = await self.calculate_average_network_tpc_cap()
            if average_network_tpc_cap is not None:
                try:
                    chain.update_current_network_tpc_capability(average_network_tpc_cap, update_min_gas_price = True)
                except NotEnoughDataForHistoricalMinGasPriceCalculation:
                    self.logger.debug("We do not have enough data to calculate min allowed gas. This will occur if our database is not synced yet.")
                    #test_1 = self.chaindb.load_historical_network_tpc_capability()
                    test_2 = self.chaindb.load_historical_minimum_gas_price()
                    #test_3 = self.chaindb.load_historical_tx_per_centisecond()
                    self.logger.debug("min_gas_price = {}".format(test_2[-10:]))

            #TODO. here we just ask for the last centisecond.
            for peer in self.peer_pool.peers:
                peer.sub_proto.send_get_min_gas_parameters(num_centiseconds_from_now=0)

        else:
            self.logger.debug("sync_min_gas_price_system, min_gas_system_ready = False")
            #here we just ask for the last 50 centiseconds.
            await self.initialize_min_gas_price_from_bootnode_if_required()


    async def initialize_min_gas_price_from_bootnode_if_required(self):
        if not self.coro_min_gas_system_ready.is_set():
            for boot_node in self.bootstrap_nodes:
                try: 
                    boot_node_peer = self.peer_pool.connected_nodes[boot_node]
                    #lets just ask the first bootnode we find that we are connected to.
                    self.logger.debug("found bootnode to ask for min_gas_price initialization")

                    earliest_required_time = get_earliest_required_time_for_min_gas_system()
                    # lets go a little further back to make sure we are fully covered
                    safe_earliest_required_time = earliest_required_time - 100 * 10

                    num_centiseconds_required = int((time.time()-safe_earliest_required_time)/100)+100

                    boot_node_peer.sub_proto.send_get_min_gas_parameters(num_centiseconds_from_now=num_centiseconds_required)
                    return
                except KeyError:
                    pass
            
        

    async def _get_missing_stake_from_bootnode(self):
        # self.logger.debug("Getting missing stake from bootnode loop start")
        addresses_needing_stake = []

        for peer in self.peer_pool.peers:
            if await self.needs_stake_from_bootnode(peer):
                addresses_needing_stake.append(peer.wallet_address)


        time_for_stake_maturity = int(time.time()) - COIN_MATURE_TIME_FOR_STAKING
        latest_timestamp = self.chain_head_db.get_latest_timestamp()

        if latest_timestamp < time_for_stake_maturity:
            addresses_needing_stake.append(self.chain_config.node_wallet_address)

        if addresses_needing_stake == []:
            return

        # self.logger.debug(self.bootstrap_nodes)
        # self.logger.debug(self.peer_pool.connected_nodes.keys())
        for boot_node in self.bootstrap_nodes:
            try:
                boot_node_peer = self.peer_pool.connected_nodes[boot_node]
                self.logger.debug("Asking bootnode for unknown peer stake")
                #lets just ask the first bootnode we find that we are connected to.
                boot_node_peer.sub_proto.send_get_stake_for_addresses(addresses_needing_stake)
                return
            except KeyError:
                self.logger.debug("We arent connected to any bootnodes to ask for stake. Saved bootstrap nodes: {}. Connected nodes: {}".format(self.bootstrap_nodes, self.peer_pool.connected_nodes.keys()))
                pass
            
        #if it gets to here, then we arent connected to any boot nodes. Or we have no bootnodes. Nothing we can do right now. Try again later.
               

    # def populate_peer_consensus(self):
    #     if self._last_block_choice_consensus_calculation_time < (int(time.time()) - CONSENSUS_SYNC_TIME_PERIOD):
    #         self._populate_peer_consensus()
    #         self._last_block_choice_consensus_calculation_time = int(time.time())
    #
    # def _populate_peer_consensus(self):
        '''
        Populates local consensus variables with the given consensus of the particular type. Doesnt account for local chain data
        '''
        #first we calculate consensus on state root timestamps
#        self.root_hash_timestamps_consensus = {}
#        oldest_allowed_time = int(time.time()) - (NUMBER_OF_HEAD_HASH_TO_SAVE)*TIME_BETWEEN_HEAD_HASH_SAVE*2
#        for timestamp, root_hash_stakes in self.root_hash_timestamps_statistics.copy().items():
#            if timestamp < oldest_allowed_time:
#                del(self.root_hash_timestamps_statistics[timestamp])
#            else:
#                self.root_hash_timestamps_consensus[timestamp] = self.determine_stake_winner(root_hash_stakes)
#

#        #now we calculate the same for conflict blocks
#        self.block_choice_consensus = {}
#        for chain_wallet_address, block_numbers in self.block_choice_statistics.items():
#            block_number_consensus = {}
#            for block_number, block_hash_stakes in block_numbers.items():
#                block_number_consensus[block_number] = self.determine_stake_winner(block_hash_stakes)
#            self.block_choice_consensus[chain_wallet_address] = block_number_consensus
#
#
    async def remove_data_for_old_root_hash_timestamps(self):
        if self._last_check_to_remove_old_local_root_hash_timestamps_from_peer_statistics < (int(time.time()) - CONSENSUS_SYNC_TIME_PERIOD):
            await self._remove_data_for_old_root_hash_timestamps()
            self._last_check_to_remove_old_local_root_hash_timestamps_from_peer_statistics = int(time.time())

    async def _remove_data_for_old_root_hash_timestamps(self):
        #cant do it by time because if the network was down for a while, and it starts back up, all of them might be too old.
        #we have to remove ones if the length gets too long
        max_allowed_length = NUMBER_OF_HEAD_HASH_TO_SAVE*2
        async with self._write_to_root_hash_timestamps_statistics:
            current_statistics_length = len(self.root_hash_timestamps_statistics)
            if current_statistics_length > max_allowed_length:
                num_to_remove = current_statistics_length - max_allowed_length
                sorted_root_hash_timestamps_statistics = SortedDict(self.root_hash_timestamps_statistics)
                for i in range(num_to_remove):
                    sorted_root_hash_timestamps_statistics.popitem(0)
                self.root_hash_timestamps_statistics = dict(sorted_root_hash_timestamps_statistics)




    def remove_data_for_blocks_that_achieved_consensus(self):
        if self._last_check_to_remove_blocks_that_acheived_consensus < (int(time.time()) - CONSENSUS_SYNC_TIME_PERIOD):
            self._remove_data_for_blocks_that_achieved_consensus()
            self._last_check_to_remove_blocks_that_acheived_consensus = int(time.time())
    

    def remove_data_for_disconnected_peers(self):
         if self._last_check_to_remove_disconnected_peer_data < (int(time.time()) - CONSENUS_PEER_DISCONNECT_CHECK_PERIOD):
            self._remove_data_for_disconnected_peers()
            self._last_check_to_remove_disconnected_peer_data = int(time.time())
    
    def _remove_data_for_disconnected_peers(self):
        connected_peer_wallet_addresses = set()
        for peer in self.peer_pool.peers:
            connected_peer_wallet_addresses.add(peer.wallet_address)
            
        for wallet_address in self.peer_root_hash_timestamps.copy().keys():
            if wallet_address not in connected_peer_wallet_addresses:
                self.logger.debug("removing root_hash_timestamps for peer {} because they have disconnected".format(wallet_address))
                del self.peer_root_hash_timestamps[wallet_address]
                

        for wallet_address in self.peer_block_choices.copy().keys():
            if wallet_address not in connected_peer_wallet_addresses:
                self.logger.debug("removing block_choices for peer {} because they have disconnected".format(wallet_address))
                del(self.peer_block_choices[wallet_address])
        
             
        
    '''
    Consensus API
    '''
    def has_block_conflict(self, chain_wallet_address: Address, block_number: BlockNumber) -> bool:
        new_block_conflict = BlockConflictInfo(chain_wallet_address, block_number)
        return new_block_conflict in self.block_conflicts

    def add_block_conflict(self, chain_wallet_address: Address, block_number: BlockNumber) -> None:
        '''
        When a conflict block is found, add it to the consensus check using this function
        '''
        self.logger.debug("Adding block conflict. Chain address {} block_number {}".format(encode_hex(chain_wallet_address), block_number))
        new_block_conflict = BlockConflictInfo(chain_wallet_address, block_number)
        self.block_conflicts.add(new_block_conflict)
        
        #lets also immediately ask peers what they have
        asyncio.ensure_future(self.send_block_conflict_messages([new_block_conflict]))



    def remove_block_conflict(self, chain_wallet_address: Address, block_number: BlockNumber) -> None:
        new_block_conflict = BlockConflictInfo(chain_wallet_address, block_number)
        try:
            self.block_conflicts.remove(new_block_conflict)
        except KeyError:
            pass
        
    #for effeciency, we can assume that we are always in consensus
    async def get_correct_block_conflict_choice_where_we_differ_from_consensus(self):
        ##{chain_wallet_address, {block_number, {[block_hash, total_stake],[block_hash, total_stake]}}
        #self.block_choice_statistics = {}
        
#        class BlockConflictInfo():
#            def __init__(self, wallet_address, block_number, timestamp):
#                self.wallet_address = wallet_address
#                self.block_number = block_number
#                self.timestamp = timestamp
#                
        #first get our local stake once
        #local_node_stake = self.chain.get_mature_stake(self.chain_config.node_wallet_address)
        try:
            local_node_stake = await self.get_accurate_stake_for_this_node()
        except UnknownPeerStake:
            # If we don't know our own stake then we cant accurately calculate consensus
            return None
        
        #now we calculate the same for conflict blocks
        consensus_block_choices_differing_from_ours = []
        for chain_address, block_numbers in self.block_choice_statistics.items():
            
            for block_number, block_hash_stakes in block_numbers.items():
                #we assume that most of the time we will be in consensus. So we don't calculate local stake unless we are in conflict with peers.
                if len(block_hash_stakes) > 0:
                    try:
                        local_block_hash = self.chaindb.get_canonical_block_hash(block_number, chain_address)
                    except HeaderNotFound:
                        local_block_hash = None
                        
                    peer_consensus_hash, total_peer_stake = self.determine_stake_winner(block_hash_stakes)
                    
                    if local_block_hash is None:
                        #if we don't have a block here, then we should get the consensus block from a peer. so add it
                        block_conflict_choice = BlockConflictChoice(chain_address, block_number, peer_consensus_hash)
                        consensus_block_choices_differing_from_ours.append(block_conflict_choice)
                        
                    else:
                        if local_block_hash != peer_consensus_hash:
                            stake_from_block_children = await self.chaindb.coro_get_block_stake_from_children(local_block_hash)
                            total_stake_from_local_node_and_chain = local_node_stake + stake_from_block_children
                            if total_stake_from_local_node_and_chain != 0:
                                try:
                                    block_hash_stakes[local_block_hash] += total_stake_from_local_node_and_chain
                                except KeyError:
                                    block_hash_stakes[local_block_hash] = total_stake_from_local_node_and_chain
                                
                                true_consensus_hash, _ = self.determine_stake_winner(block_hash_stakes)
                                
                                if true_consensus_hash != local_block_hash:
                                    block_conflict_choice = BlockConflictChoice(chain_address, block_number, true_consensus_hash)
                                    consensus_block_choices_differing_from_ours.append(block_conflict_choice)
                            else:
                                block_conflict_choice = BlockConflictChoice(chain_address, block_number, peer_consensus_hash)
                                consensus_block_choices_differing_from_ours.append(block_conflict_choice)
                
        if len(consensus_block_choices_differing_from_ours) == 0:
            return None
        else:
            return consensus_block_choices_differing_from_ours
        
    def get_peers_who_have_conflict_block(self, block_hash):
#        #{peer_wallet_address, [peer_stake, [hls.BlockHashKey]]}
#        self.peer_block_choices = {}
        peer_wallet_addresses_with_block = []
        for peer_wallet_address, peer_stake_block_hash_keys in self.peer_block_choices.items():
            block_hash_keys = peer_stake_block_hash_keys[1]
            for block_hash_key in block_hash_keys:
                if block_hash_key.block_hash == block_hash:
                    peer_wallet_addresses_with_block.append(peer_wallet_address)
                    break
                
        peers_with_block = []
        for wallet_address in peer_wallet_addresses_with_block:
            try:
                peers_with_block.append(self.peer_pool.wallet_address_to_peer_lookup[wallet_address])
            except KeyError:
                pass
            
        if len(peers_with_block) == 0:
            return None
        else:
            return peers_with_block
        
    #
    # async def get_closest_root_hash_consensus(self, timestamp):
    #     '''
    #     Returns the closest timestamp that we have a saved root hash for
    #     '''
    #     sorted_root_hash_timestamps = reversed(SortedDict(self.root_hash_timestamps_statistics))
    #     #goes from greatest to smallest
    #     for available_timestamp in sorted_root_hash_timestamps.keys():
    #         if available_timestamp <= timestamp:
    #             to_return =  available_timestamp, await self.coro_get_root_hash_consensus(available_timestamp)
    #             return to_return
    #
    #     if self.is_network_startup_node:
    #         self.logger.debug("using local root hash timestamps for get_closest_root_hash_consensus because am bootnode")
    #         local_root_hash_timestamps = self.local_root_hash_timestamps
    #         sorted_local_root_hash_timestamps = SortedDict(lambda x: int(x)*-1, local_root_hash_timestamps)
    #         for available_timestamp, root_hash in sorted_local_root_hash_timestamps.items():
    #             if available_timestamp <= timestamp:
    #                 to_return =  available_timestamp, root_hash
    #                 return to_return
    #
    #
    #     return None, None
    
    
    # def get_next_consensus_root_hash_after_timestamp_that_differs_from_local_at_timestamp(self, timestamp):
    #     '''
    #     Returns the next consensus root hash that differs from our local root hash at the given timestamp
    #     '''
    #     initial_local_root_hash_at_timestamp = self.local_root_hash_timestamps[timestamp]
    #     #self.logger.debug("initial root hash = {}".format(initial_local_root_hash_at_timestamp))
    #     #self.logger.debug("consensus root hash at initial timestamp = {}".format(self.get_root_hash_consensus(timestamp)))
    #     sorted_root_hash_timestamps = SortedDict(self.root_hash_timestamps_statistics)
    #     #goes from smallest to greatest
    #     for available_timestamp in sorted_root_hash_timestamps.keys():
    #         if available_timestamp > timestamp:
    #             to_return =  available_timestamp, self.get_root_hash_consensus(available_timestamp)
    #             if to_return[1] != initial_local_root_hash_at_timestamp:
    #                 return to_return
    #
    #     if self.is_network_startup_node:
    #         self.logger.debug("using local root hash timestamps for get_next_consensus_root_hash_after_timestamp because am bootnode")
    #         local_root_hash_timestamps = self.local_root_hash_timestamps
    #         sorted_local_root_hash_timestamps = SortedDict(local_root_hash_timestamps)
    #         for available_timestamp, root_hash in sorted_local_root_hash_timestamps.items():
    #             if available_timestamp > timestamp:
    #                 to_return =  available_timestamp, root_hash
    #                 if to_return[1] != initial_local_root_hash_at_timestamp:
    #                     return to_return
    #
    #     return None, None
    
    # def get_next_consensus_root_hash_after_timestamp(self, timestamp):
    #     '''
    #     Returns the next consensus root hash that differs from our local root hash at the given timestamp
    #     '''
    #     #initial_local_root_hash_at_timestamp = self.local_root_hash_timestamps[timestamp]
    #     #self.logger.debug("initial root hash = {}".format(initial_local_root_hash_at_timestamp))
    #     #self.logger.debug("consensus root hash at initial timestamp = {}".format(self.get_root_hash_consensus(timestamp)))
    #     sorted_root_hash_timestamps = SortedDict(self.root_hash_timestamps_statistics)
    #     #goes from smallest to greatest
    #     for available_timestamp in sorted_root_hash_timestamps.keys():
    #         if available_timestamp > timestamp:
    #             to_return =  available_timestamp, self.get_root_hash_consensus(available_timestamp)
    #             return to_return
    #
    #     if self.is_network_startup_node:
    #         self.logger.debug("using local root hash timestamps for get_next_consensus_root_hash_after_timestamp because am bootnode")
    #         local_root_hash_timestamps = self.local_root_hash_timestamps
    #         sorted_local_root_hash_timestamps = SortedDict(local_root_hash_timestamps)
    #         for available_timestamp, root_hash in sorted_local_root_hash_timestamps.items():
    #             if available_timestamp > timestamp:
    #                 to_return =  available_timestamp, root_hash
    #                 return to_return
    #
    #     return None, None
        
        
        
    
    def get_newest_peer_root_hash_timestamp(self):
        if len(self.root_hash_timestamps_statistics) > 0:
            try:
                return list(SortedDict(self.root_hash_timestamps_statistics).keys())[-1]
            except TypeError:
                pass
        else:
            return None
        
    
    @property
    def local_root_hash_timestamps(self):
        local_root_hash_timestamps = self.chain_head_db.get_dense_historical_root_hashes()
        
        if local_root_hash_timestamps is not None:
            self._local_root_hash_timestamps = dict(local_root_hash_timestamps)
        else:
            self._local_root_hash_timestamps = None
        
        return self._local_root_hash_timestamps

    async def coro_get_root_hash_consensus(self, timestamp, local_root_hash_timestamps = None, debug = False):
        '''
        Returns the consensus root hash for a given timestamp
        '''


        timestamp = round_down_to_nearest_historical_window(timestamp)
        if local_root_hash_timestamps is None:
            local_root_hash_timestamps = self.local_root_hash_timestamps
            
        if local_root_hash_timestamps is not None:
            try:
                local_root_hash = local_root_hash_timestamps[timestamp]
            except KeyError:
                local_root_hash = None
        else:
            local_root_hash = None

        try:
            root_hash_stakes = self.root_hash_timestamps_statistics[timestamp]
            peer_root_hash, peer_stake_for_peer_root_hash = self.determine_stake_winner(root_hash_stakes)
        except KeyError:
            return None

        if peer_root_hash == local_root_hash or local_root_hash is None:
            return peer_root_hash
        else:
            try:
                our_stake_for_local_hash = await self.get_accurate_stake_for_this_node()
            except UnknownPeerStake:
                # In this case, we have no blockchain for this node, and we havent recevied our stake from the bootnode yet.
                return None
            try:
                peer_stake_for_local_hash = self.root_hash_timestamps_statistics[timestamp][local_root_hash]
            except KeyError:
                peer_stake_for_local_hash = 0
            total_stake_for_local_hash = our_stake_for_local_hash + peer_stake_for_local_hash


            to_return = self.get_winner_stake_binary_compare(peer_root_hash,
                                                        peer_stake_for_peer_root_hash, 
                                                        local_root_hash, 
                                                        total_stake_for_local_hash)

            return to_return
            
    # def get_root_hash_consensus(self, timestamp, local_root_hash_timestamps = None):
    #     '''
    #     Returns the consensus root hash for a given timestamp
    #     '''
    #     if local_root_hash_timestamps is None:
    #         local_root_hash_timestamps = self.local_root_hash_timestamps
    #     if local_root_hash_timestamps is not None:
    #         try:
    #             local_root_hash = local_root_hash_timestamps[timestamp]
    #         except KeyError:
    #             local_root_hash = None
    #     else:
    #         local_root_hash = None
    #
    #
    #     try:
    #         root_hash_stakes = self.root_hash_timestamps_statistics[timestamp]
    #         peer_root_hash, peer_stake_for_peer_root_hash = self.determine_stake_winner(root_hash_stakes)
    #     except KeyError:
    #         return local_root_hash
    #
    #     if peer_root_hash == local_root_hash or local_root_hash is None:
    #         return peer_root_hash
    #     else:
    #         our_stake_for_local_hash = self.chain.get_mature_stake(self.chain_config.node_wallet_address)
    #         try:
    #             peer_stake_for_local_hash = self.root_hash_timestamps_statistics[timestamp][local_root_hash]
    #         except KeyError:
    #             peer_stake_for_local_hash = 0
    #         total_stake_for_local_hash = our_stake_for_local_hash + peer_stake_for_local_hash
    #
    #         return self.get_winner_stake_binary_compare(peer_root_hash,
    #                                                     peer_stake_for_peer_root_hash,
    #                                                     local_root_hash,
    #                                                     total_stake_for_local_hash)

    async def get_blockchain_sync_parameters(self, debug = False) -> Optional[SyncParameters]:
        '''
        This returns parameters that the syncer needs to perform sync
        :return:
        '''

        # We start one hash before the correct one, because if that one is also incorrect, then we havent synced up to
        # the time where additive syncing can occur.

        do_fast_sync = False

        earliest_allowed_time = int((int(time.time()) - NUMBER_OF_HEAD_HASH_TO_SAVE * TIME_BETWEEN_HEAD_HASH_SAVE)/1000)*1000

        disagreement_found = False
        local_root_hash_timestamps = self.local_root_hash_timestamps


        if local_root_hash_timestamps is not None:

            #we run the loop from newest to oldest because the db is most often going to be close to syncing. This will be more effecient
            sorted_local_root_hash_timestamps = SortedDict(lambda x: int(x) * -1, local_root_hash_timestamps)
            #we can assume the root hashes are dense and go up to the currently filling window

            previous_consensus_root_hash = None
            previous_local_root_hash = None
            previous_timestamp = None
            num_checked = 0

            # it now goes from newest to oldest
            for timestamp, local_root_hash in sorted_local_root_hash_timestamps.items():

                consensus_root_hash = await self.coro_get_root_hash_consensus(timestamp, local_root_hash_timestamps=local_root_hash_timestamps)

                if local_root_hash == consensus_root_hash:
                    if debug:
                        self.logger.debug("get_blockchain_sync_parameters Matched at timestamp {}".format(timestamp))
                    if disagreement_found:
                        # this is the first agreeing one after some disagreeing ones. This is what we return
                        if timestamp <= earliest_allowed_time:
                            if debug:
                                self.logger.debug("get_blockchain_sync_parameters forcing fast sync {}. earliest allowed timestamp {}".format(timestamp,earliest_allowed_time))
                            do_fast_sync = True
                            break

                        peers_to_sync_with = []

                        for peer in self.peer_pool.peers:
                            if self.get_chain_head_root_hash_for_peer(peer.wallet_address, previous_timestamp) == previous_consensus_root_hash:
                                peers_to_sync_with.append(peer)


                        if len(peers_to_sync_with) == 0:

                            raise NoEligiblePeers("No peers have the root hash that we need to sync with. They may have just disconnected.")

                        sync_params = SyncParameters(previous_timestamp,
                                              local_root_hash=previous_local_root_hash,
                                              consensus_root_hash=previous_consensus_root_hash,
                                              peers_to_sync_with=peers_to_sync_with)
                        self.current_sync_stage = sync_params.sync_stage
                        return sync_params

                    else:
                        # we are in agreemenet from the newest roothash without any disagreements, we break and return none
                        break
                else:
                    disagreement_found = True
                    # if we get to the end, and disagreements were found, that means the entire database is in disagreement.
                    # Will throw an error below.

                previous_consensus_root_hash = consensus_root_hash
                previous_local_root_hash = local_root_hash
                previous_timestamp = timestamp

                num_checked += 1
                if num_checked >= 10:
                    if not disagreement_found:
                        #if the newest 10 chronological block timestamps are correct, no point in checking more.
                        break


        if local_root_hash_timestamps is None or disagreement_found or do_fast_sync:
            if debug:
                self.logger.debug("get_blockchain_sync_parameters second part")

            # Ours disagrees all of the way through. We need to perform a fast sync, or stage 1 sync.
            # By default, lets perform the fast sync up to the root hash from 24 hours ago.
            fast_sync_chronological_block_hash_timestamp = Timestamp(int((time.time() - TIME_OFFSET_TO_FAST_SYNC_TO) / 1000) * 1000)

            if local_root_hash_timestamps is None:
                local_root_hash = BLANK_ROOT_HASH
            else:
                try:
                    local_root_hash = local_root_hash_timestamps[fast_sync_chronological_block_hash_timestamp]
                except KeyError:
                    local_root_hash = BLANK_ROOT_HASH


            consensus_root_hash = await self.coro_get_root_hash_consensus(fast_sync_chronological_block_hash_timestamp, local_root_hash_timestamps=local_root_hash_timestamps)


            if consensus_root_hash is None:
                raise NoEligiblePeers("There are no peers that have the root hash we need for fast sync.")

            peers_to_sync_with = []

            for peer in self.peer_pool.peers:
                if self.get_chain_head_root_hash_for_peer(peer.wallet_address, fast_sync_chronological_block_hash_timestamp) == consensus_root_hash:
                    peers_to_sync_with.append(peer)


            if len(peers_to_sync_with) == 0:
                raise NoEligiblePeers("No peers have the root hash that we need to sync with. They may have just disconnected.")

            sync_params = SyncParameters(fast_sync_chronological_block_hash_timestamp,
                               local_root_hash=local_root_hash,
                               consensus_root_hash=consensus_root_hash,
                               peers_to_sync_with=peers_to_sync_with,
                               sync_stage_override = 1)
            self.current_sync_stage = sync_params.sync_stage
            return sync_params


        else:
            self.current_sync_stage = 4
            return None



            
        
    
    #TODO. make sure we remove conflict blocks that reach consensus   
    async def get_block_conflict_consensus(self, chain_wallet_address, block_number):
        '''
        Returns the block hash of the block that has consensus for a given block_conflict.
        '''
        #first lets double check which block hash we have:
        #TODO: might want to streamlinethis by storing it in the local variable
        try:
            local_block_hash = await self.chaindb.coro_get_canonical_block_hash(block_number, chain_wallet_address)
        except HeaderNotFound:
            local_block_hash = None
        
#        self.block_choice_consensus = {}
#        for chain_wallet_address, block_numbers in self.block_choice_statistics.items():
#            block_number_consensus = {}
#            for block_number, block_hash_stakes in block_numbers.items():
#                block_number_consensus[block_number] = self.determine_stake_winner(block_hash_stakes)
#            self.block_choice_consensus[chain_wallet_address] = block_number_consensus
#            
            
        
        try:
            block_hash_stakes = self.block_choice_statistics[chain_wallet_address][block_number]
            peer_consensus_block_hash, peer_consensus_block_stake = self.determine_stake_winner(block_hash_stakes)
            #peer_consensus_block_hash, peer_consensus_block_stake = self.block_choice_consensus[chain_wallet_address][block_number]
        except KeyError:
            return local_block_hash
        

        if local_block_hash is None:
            return peer_consensus_block_hash
        else:
            if local_block_hash != peer_consensus_block_hash:
                #the peers have chosen something different than what we have here
                #At this point we calculate the stake of all children blocks that come after it
                #However, we don't want to count any nodes that have voted here incase their vote changed
                exclude_chains = set(self.peer_block_choices.keys())
                children_stake_for_local_block = await self.chaindb.coro_get_block_stake_from_children(local_block_hash, exclude_chains = exclude_chains)

                try:
                    our_stake_for_local_block = await self.get_accurate_stake_for_this_node()
                except UnknownPeerStake:
                    # In this case, we have no blockchain for this node, and we havent recevied our stake from the bootnode yet.
                    return None

                try:
                    peer_stake_for_local_block = self.block_choice_statistics[chain_wallet_address][block_number][local_block_hash]
                except KeyError:
                    peer_stake_for_local_block = 0
                total_stake_for_local_block =  peer_stake_for_local_block + children_stake_for_local_block + our_stake_for_local_block

                return self.get_winner_stake_binary_compare(peer_consensus_block_hash,
                                                            peer_consensus_block_stake,
                                                            local_block_hash,
                                                            total_stake_for_local_block)
                



    '''
    message handling stuff
    '''
    async def _handle_msg(self, peer: HLSPeer, cmd: protocol.Command,
                          msg: protocol._DecodedMsgType) -> None:
        #TODO: change these to use something else other than isinstance. Check the command id and offset maybe?
        if isinstance(cmd, UnorderedBlockHeaderHash):
            await self._handle_block_choices(peer, cast(List[BlockHashKey], msg))

        elif isinstance(cmd, GetUnorderedBlockHeaderHash):
            await self._handle_get_block_choices(peer, cast(List[BlockNumberKey], msg))

        elif isinstance(cmd, ChainHeadRootHashTimestamps):
            await self._handle_chain_head_root_hash_timestamps(peer, cast(List[Any], msg))
            
        elif isinstance(cmd, GetChainHeadRootHashTimestamps):
            await self._handle_get_chain_head_root_hash_timestamps(peer, cast(Dict[str, Any], msg))
        
        elif isinstance(cmd, StakeForAddresses):
            await self._handle_stake_for_addresses(peer, cast(Dict[str, Any], msg))
            
        elif isinstance(cmd, GetStakeForAddresses):
            if await self.current_sync_stage >= 2 or self.chain_config.network_startup_node:
                await self._handle_get_stake_for_addresses(peer, cast(Dict[str, Any], msg))
            
        elif isinstance(cmd, GetMinGasParameters):
            await self._handle_get_min_gas_parameters(peer, cast(Dict[str, Any], msg))
            
        elif isinstance(cmd, MinGasParameters):
            await self._handle_min_gas_parameters(peer, cast(Dict[str, Any], msg))

        elif isinstance(cmd, GetNodeStakingScore):
            if await self.current_sync_stage >= 4 or self.chain_config.network_startup_node:
                await self._handle_get_node_staking_score(peer, cast(NodeStakingScore, msg))


        
        


    async def _handle_block_choices(self, peer: HLSPeer, msg) -> None:
        peer_wallet_address = peer.wallet_address
        #self.logger.debug("handle_block_chioces msg = {}".format(msg))
        try:
            stake = await self.get_accurate_stake(peer)

            new_peer_block_choice = PeerBlockChoice(peer_wallet_address, stake, msg)
            self._new_peer_block_choices.put_nowait(new_peer_block_choice)
        except UnknownPeerStake:
            #If we don't know their stake yet. Don't add it to the statistics.
            pass
            
    async def _handle_get_block_choices(self, peer: HLSPeer, msg) -> None:
        #self.logger.debug("_handle_get_block_choices msg = {}".format(msg))        
        #lets get the data and send it back
        block_keys = msg
        return_data = []
        for block_key in block_keys:
            try:
                block_hash = self.chaindb.get_canonical_block_hash(block_key.block_number, block_key.wallet_address)
                return_data.append(BlockHashKey(wallet_address = block_key.wallet_address, block_number = block_key.block_number, block_hash = block_hash))
            except HeaderNotFound:
                pass
            
        if len(return_data) > 0:
            peer.sub_proto.send_unordered_block_header_hash(return_data)
      
        
    async def _handle_chain_head_root_hash_timestamps(self, peer: HLSPeer, msg) -> None:
        peer_wallet_address = peer.wallet_address
        #self.logger.debug("_handle_chain_head_root_hash_timestamps msg = {}".format(msg))
        try:
            stake = await self.get_accurate_stake(peer)

            new_root_hash_timestamps = msg
            #lets save it to the peer
            peer.chain_head_root_hashes = new_root_hash_timestamps
            new_peer_data = PeerRootHashTimestamps(peer_wallet_address, stake, new_root_hash_timestamps)
            self._new_peer_chain_head_root_hash_timestamps.put_nowait(new_peer_data)
        except UnknownPeerStake:
            self.logger.debug("Received chain head root hash timestamps from a peer with unknown stake")
            # If we don't know their stake yet. Don't add it to the statistics.
            pass
            
    async def _handle_get_chain_head_root_hash_timestamps(self, peer: HLSPeer, msg) -> None:
        #peer_wallet_address = peer.wallet_address
        #self.logger.debug("_handle_get_chain_head_root_hash_timestamps msg = {}".format(msg))       
        #lets get the data and send it back
        return_data = await self.chain_head_db.coro_get_dense_historical_root_hashes(msg['after_timestamp'])
        if return_data is not None:
            #self.logger.debug("_handle_get_chain_head_root_hash_timestamps return_data = {}".format(return_data))
            peer.sub_proto.send_chain_head_root_hash_timestamps(return_data)
            
    async def _handle_stake_for_addresses(self, peer: HLSPeer, msg) -> None:
        #make sure it is a bootstrap node
        self.logger.debug("Received missing stake from bootnode")
        if peer.remote in self.bootstrap_nodes:
            for address_stake in msg['stakes']:
                address = address_stake[0]
                stake = address_stake[1]
                self.peer_stake_from_bootstrap_node[address] = stake

            
    async def _handle_get_stake_for_addresses(self, peer: HLSPeer, msg) -> None:
        self.logger.debug("Received request for stake for some addresses")
        address_stakes = []
        for address in msg['addresses']:
            stake = await self.chaindb.coro_get_mature_stake(address)
            address_stakes.append([address,stake])
        peer.sub_proto.send_stake_for_addresses(address_stakes)
        
    async def _handle_get_min_gas_parameters(self, peer: HLSPeer, msg) -> None:
        if self.coro_min_gas_system_ready.is_set():
            hist_min_allowed_gas_price = await self.chaindb.coro_load_historical_minimum_gas_price(sort=True)
            
            if msg['num_centiseconds_from_now'] == 0:
                average_network_tpc_cap = await self.calculate_average_network_tpc_cap()
                if average_network_tpc_cap is not None:
                    hist_net_tpc_capability = [[0, average_network_tpc_cap]]
                    hist_min_allowed_gas_price_new = [[0,hist_min_allowed_gas_price[-1][1]]]
                    peer.sub_proto.send_min_gas_parameters(hist_net_tpc_capability, hist_min_allowed_gas_price_new)
            else:
                hist_net_tpc_capability = await self.chaindb.coro_load_historical_network_tpc_capability(sort=True)
                
                num_centiseconds_to_send = min([len(hist_net_tpc_capability), len(hist_min_allowed_gas_price), msg['num_centiseconds_from_now']])
                self.logger.debug("sending {} centiseconds of min gas parameters".format(num_centiseconds_to_send))
                peer.sub_proto.send_min_gas_parameters(hist_net_tpc_capability[-num_centiseconds_to_send:], hist_min_allowed_gas_price[-num_centiseconds_to_send:])
                
    async def _handle_min_gas_parameters(self, peer: HLSPeer, msg) -> None:
        
        hist_net_tpc_capability = msg['hist_net_tpc_capability']
        hist_min_allowed_gas_price = msg['hist_min_allowed_gas_price']
        
        if len(hist_net_tpc_capability) == 1:
            #require that the timestamp is set to 0 for the most recent average. Otherwise we shouldn't be receiving just 1.
            if hist_net_tpc_capability[0][0] == 0:
                #We are just receiving the last minute. this can be from any node. Lets keep track of it and average it.
                try:
                    stake = await self.get_accurate_stake(peer)
                    self._network_tpc_cap_statistics[peer.wallet_address] = [time.time(),hist_net_tpc_capability[0][1], stake]
                except UnknownPeerStake:
                    # If we don't know their stake yet. Don't add it to the statistics.
                    pass

        else:
            #we are receiving an entire list of historical tpc data. This can only come from a bootnode.
            if peer.remote in self.bootstrap_nodes:
                if not self.coro_min_gas_system_ready.is_set():
                    await self.chaindb.coro_save_historical_minimum_gas_price(hist_min_allowed_gas_price)
                    await self.chaindb.coro_save_historical_network_tpc_capability(hist_net_tpc_capability)

    async def _handle_get_node_staking_score(self, peer: HLSPeer, msg) -> None:
        self.logger.debug("Received request to send node staking score.")
        if peer.wallet_address != self.chain_config.node_wallet_address:
            try:
                node_staking_score = await self.consensus_db.coro_get_signed_peer_score_string_private_key(self.chain_config.node_private_helios_key.to_bytes(), self.node.get_chain().network_id, peer.wallet_address)
            except (ValueError, CanonicalHeadNotFound) as e:
                self.logger.warning("Failed to create node staking score for peer {}. Error: {}".format(encode_hex(peer.wallet_address), e))
            else:
                self.logger.debug("Sending node staking score.")
                peer.sub_proto.send_node_staking_score(node_staking_score)

    #
    # Event bus functions
    #
    async def handle_event_bus_events(self) -> None:
        async def stake_from_bootnode_loop() -> None:
            # FIXME: There must be a way to cancel event_bus.stream() when our token is triggered,
            # but for the time being we just wrap everything in self.wait().
            async for req in self.event_bus.stream(StakeFromBootnodeRequest):
                self.event_bus.broadcast(StakeFromBootnodeResponse(self.peer_stake_from_bootstrap_node), req.broadcast_config())

        async def current_sync_stage_loop() -> None:
            # FIXME: There must be a way to cancel event_bus.stream() when our token is triggered,
            # but for the time being we just wrap everything in self.wait().
            async for req in self.event_bus.stream(CurrentSyncStageRequest):
                self.event_bus.broadcast(CurrentSyncStageResponse(await self.current_sync_stage),
                                         req.broadcast_config())

        async def current_syncing_parameters_loop() -> None:
            # FIXME: There must be a way to cancel event_bus.stream() when our token is triggered,
            # but for the time being we just wrap everything in self.wait().
            async for req in self.event_bus.stream(CurrentSyncingParametersRequest):
                self.event_bus.broadcast(CurrentSyncingParametersResponse(await self.get_blockchain_sync_parameters()),
                                         req.broadcast_config())

        await self.wait_first(stake_from_bootnode_loop(),current_sync_stage_loop(), current_syncing_parameters_loop())


                
            
            

            
            
            
            
            
            