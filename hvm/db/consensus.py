import time
from typing import TYPE_CHECKING
from uuid import UUID
import logging
from lru import LRU
from typing import Set, Tuple  # noqa: F401


from eth_typing import (
    BlockNumber,
    Hash32,
    Address,
)

import rlp

from trie import (
    BinaryTrie,
    HexaryTrie,
)

from eth_hash.auto import keccak
from eth_utils import encode_hex

from hvm.constants import (
    TIME_BETWEEN_PEER_NODE_HEALTH_CHECK,
    PEER_NODE_HEALTH_CHECK_RESPONSE_TIME_PENALTY_START_MS,
    PEER_NODE_HEALTH_CHECK_RESPONSE_TIME_PENALTY_50_PERCENT_REDUCTION_MS,
)
from hvm.db.batch import (
    BatchDB,
)
from hvm.db.cache import (
    CacheDB,
)
from hvm.db.journal import (
    JournalDB,
)
from hvm.rlp.accounts import (
    Account,
    TransactionKey,
)
from hvm.validation import (
    validate_is_bytes,
    validate_uint256,
    validate_uint64,
    validate_canonical_address,
)

from hvm.utils.numeric import (
    int_to_big_endian,
    add_sample_to_average,
)
from hvm.utils.padding import (
    pad32,
)

from hvm.db.schema import SchemaV1

from .hash_trie import HashTrie

from hvm.rlp.sedes import(
    trie_root,
    hash32,
)

from rlp.sedes import (
    big_endian_int,
    f_big_endian_int,
    CountableList,
    binary,
    List
)
from eth_utils import (
    int_to_big_endian,
    big_endian_to_int,
)
import itertools
import math
from hvm.exceptions import (
    InvalidHeadRootTimestamp,
    HeaderNotFound,
)

from hvm.rlp.consensus import (
    PeerNodeHealth,
    NodeStakingScore,
)
from hvm.db.backends.base import BaseDB

if TYPE_CHECKING:
    from hvm.db.chain import BaseChainDB

# Use lru-dict instead of functools.lru_cache because the latter doesn't let us invalidate a single
# entry, so we'd have to invalidate the whole cache in _set_account() and that turns out to be too
# expensive.
account_cache = LRU(2048)


class ConsensusDB():

    db: BaseDB = None
    chaindb: 'BaseChainDB' = None

    logger = logging.getLogger('hvm.db.chain_head.ChainHeadDB')

    def __init__(self, db:BaseDB, chaindb:'BaseChainDB'):
        """
        Binary trie database for storing the hash of the head block of each wallet address.
        """
        self.db = db
        self.chaindb = chaindb

    #
    # Peer node health API
    #

    # lookup key holds peer wallet address and previous reward block number
    #
    # rlp_templates encoded object holds:
    # average response time
    # num requests sent
    # num failed replies

    # send requests once per hour. Then we can calculate amount of uptime that this node saw by num requests sent * 1 hour.
    # new avg response time = prev avg response time * (n-1)/n + new response time/n

    # we want to base the reward on amount of uptime, average response time, and num failed requests.

    # A node that is still syncing will have lots of failed requests, but we shouldn't penalize them because they are still
    # syncing. So lets keep things simple. Just base score on uptime and response time. Therefore, a syncing node will just
    # not have its time counted towards uptime until it finishes syncing and responds to requests.

    # note: whenever a reward block is processed, we need to save the block number
    # note: when reverting blocks, if one has a reward transaction then need to update get_latest_reward_block_number
    # also need to add all of the new health request statistics to the previous health request for the previous after_block_number

    def save_health_request(self, peer_wallet_address: Address, response_time: int = float('inf')):

        after_block_number = self.get_latest_reward_block_number(peer_wallet_address)
        peer_node_health = self._get_peer_node_health(peer_wallet_address, after_block_number)

        # ('requests_sent', f_big_endian_int),
        # ('failed_requests', f_big_endian_int),
        # ('average_response_time', f_big_endian_int)  # milliseconds
        #

        new_requests_sent = peer_node_health.requests_sent + 1
        if response_time == float('inf'):
            #it didn't respond
            new_failed_requests = peer_node_health.failed_requests + 1
            new_average_response_time = peer_node_health.average_response_time
        else:
            new_failed_requests = peer_node_health.failed_requests
            new_average_response_time = add_sample_to_average(peer_node_health.average_response_time, response_time, new_requests_sent)

        self._set_peer_node_health(peer_wallet_address, after_block_number, peer_node_health.copy(requests_sent = new_requests_sent,
                                                                                                  failed_requests = new_failed_requests,
                                                                                                  average_response_time = new_average_response_time))


    def get_latest_reward_block_number(self, peer_wallet_address: Address) -> int:
        validate_canonical_address(peer_wallet_address, title="peer_wallet_address")

        key = SchemaV1.make_latest_reward_block_number_lookup(peer_wallet_address)
        rlp_latest_block_number = self.db.get(key, b'')
        if rlp_latest_block_number:
            return rlp.decode(rlp_latest_block_number, sedes = f_big_endian_int)
        else:
            return 0


    def set_latest_reward_block_number(self, peer_wallet_address: Address, block_number: int) -> None:
        validate_canonical_address(peer_wallet_address, title="peer_wallet_address")

        key = SchemaV1.make_latest_reward_block_number_lookup(peer_wallet_address)

        self.db[key] = rlp.encode(block_number, sedes = f_big_endian_int)


    def get_peer_score(self, peer_wallet_address: Address, after_block_number: BlockNumber) -> NodeStakingScore:
        peer_node_health = self._get_peer_node_health(peer_wallet_address, after_block_number)

        # fields = [
        #     ('recipient_node_wallet_address', address),
        #     ('score', f_big_endian_int),
        #     ('since_block_number', f_big_endian_int),
        #     ('timestamp', f_big_endian_int),
        #     ('v', f_big_endian_int),
        #     ('r', f_big_endian_int),
        #     ('s', f_big_endian_int),
        # ]

        #need to get the time since the block.
        try:
            header = self.chaindb.get_canonical_block_header_by_number(after_block_number, peer_wallet_address)
        except HeaderNotFound:
            raise ValueError("Cannot find previous block that is supposed to contain a stake reward")

        since_timestamp = header.timestamp
        time_since_last_specified_block = int(time.time()) - since_timestamp

        score = self.calculate_node_staking_score(peer_node_health.requests_sent,
                                                  peer_node_health.failed_requests,
                                                  peer_node_health.average_response_time,
                                                  time_since_last_specified_block)

        return NodeStakingScore(peer_wallet_address, score, after_block_number, int(time.time()))


    def calculate_node_staking_score(self, requests_sent: int, failed_requests: int, average_response_time: int, time_since_last_reward) -> int:
        '''
        returns a score out of 1,000,000. Increased resolution to 1 million so that nodes that go for a very long time without getting their reward dont average to 0.
        This uses a f = A/(x+A) function to calculate score lost to response time.
        Also bases the score on the percentage of time since last reward that the node was online.
        :param requests_sent:
        :param failed_requests:
        :param average_response_time:
        :return:
        '''

        PEER_NODE_HEALTH_CHECK_RESPONSE_TIME_PENALTY_50_PERCENT_REDUCTION_MS = 1000

        uptime = (requests_sent - failed_requests) * TIME_BETWEEN_PEER_NODE_HEALTH_CHECK

        uptime_multiplier = uptime/time_since_last_reward

        average_response_time_past_pentalty_start = average_response_time - PEER_NODE_HEALTH_CHECK_RESPONSE_TIME_PENALTY_START_MS
        if average_response_time_past_pentalty_start < 0:
            average_response_time_past_pentalty_start = 0

        response_time_multiplier = ((PEER_NODE_HEALTH_CHECK_RESPONSE_TIME_PENALTY_50_PERCENT_REDUCTION_MS-PEER_NODE_HEALTH_CHECK_RESPONSE_TIME_PENALTY_START_MS)/
                                    (average_response_time_past_pentalty_start+
                                     PEER_NODE_HEALTH_CHECK_RESPONSE_TIME_PENALTY_50_PERCENT_REDUCTION_MS-
                                     PEER_NODE_HEALTH_CHECK_RESPONSE_TIME_PENALTY_START_MS))

        score = int(uptime_multiplier*response_time_multiplier*1000000)

        return score



    #
    # Internal
    #
    def _get_peer_node_health(self, peer_wallet_address: Address, after_block_number: BlockNumber) -> PeerNodeHealth:
        validate_canonical_address(peer_wallet_address, title="Value")
        validate_uint64(after_block_number, 'block_number')

        key = SchemaV1.make_peer_node_health_lookup(peer_wallet_address, after_block_number)
        rlp_peer_node_health = self.db.get(key, b'')
        if rlp_peer_node_health:
            peer_node_health = rlp.decode(rlp_peer_node_health, sedes=PeerNodeHealth)
        else:
            peer_node_health = PeerNodeHealth()
        return peer_node_health

    def _set_peer_node_health(self, peer_wallet_address: Address, after_block_number: BlockNumber, peer_node_health: PeerNodeHealth) -> None:
        encoded_peer_node_health = rlp.encode(peer_node_health, sedes=PeerNodeHealth)
        key = SchemaV1.make_peer_node_health_lookup(peer_wallet_address, after_block_number)
        self.db[key] = encoded_peer_node_health

 

    
  



        
    
    
    
    
    
    
    
    
    
    