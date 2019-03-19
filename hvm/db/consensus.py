import time
from typing import TYPE_CHECKING
from uuid import UUID
import logging
from lru import LRU
from typing import (
    List,
    Tuple,
)


from eth_typing import (
    BlockNumber,
    Hash32,
    Address,
)

from eth_utils import encode_hex

from hvm.types import Timestamp

from eth_keys.datatypes import(
        PrivateKey
)

from eth_keys import keys

import rlp_cython as rlp

from hvm.constants import (
    TIME_BETWEEN_PEER_NODE_HEALTH_CHECK,
    PEER_NODE_HEALTH_CHECK_RESPONSE_TIME_PENALTY_START_MS,
    PEER_NODE_HEALTH_CHECK_RESPONSE_TIME_PENALTY_50_PERCENT_REDUCTION_MS,
    REQUIRED_STAKE_FOR_REWARD_TYPE_2_PROOF,
    REQUIRED_NUMBER_OF_PROOFS_FOR_REWARD_TYPE_2_PROOF,
    REWARD_TYPE_2_AMOUNT_FACTOR,
    REWARD_TYPE_1_AMOUNT_FACTOR,
    COIN_MATURE_TIME_FOR_STAKING,
    MIN_ALLOWED_TIME_BETWEEN_REWARD_BLOCKS,
    REWARD_PROOF_TIMESTAMP_VARIABILITY_ALLOWANCE,
    REWARD_BLOCK_AND_BUNDLE_TIMESTAMP_VARIABILITY_ALLOWANCE,
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
from hvm.db.schema import SchemaV1



import rlp_cython.sedes as sedes

from hvm.exceptions import (
    InvalidHeadRootTimestamp,
    HeaderNotFound,
    NotEnoughProofsOrStakeForRewardType2Proof,
    ValidationError,
    RewardProofSenderBlockMissing,
)

from hvm.rlp.consensus import (
    PeerNodeHealth,
    NodeStakingScore,
    StakeRewardBundle,
    StakeRewardType1,
    StakeRewardType2,
)
from hvm.db.backends.base import BaseDB
from hvm.utils.numeric import stake_weighted_average

if TYPE_CHECKING:
    from hvm.db.chain import BaseChainDB
    from hvm.chains.base import BaseChain



class ConsensusDB():

    db: BaseDB = None
    chaindb: 'BaseChainDB' = None

    logger = logging.getLogger('hvm.db.consensus.ConsensusDB')

    def __init__(self, chaindb:'BaseChainDB'):
        """
        Binary trie database for storing the hash of the head block of each wallet address.
        """
        self.db = chaindb.db
        self.chaindb = chaindb

        self.logger.debug("starting consensus db")

    #
    # Peer node health API
    #

    def save_health_request(self, peer_wallet_address: Address, response_time_in_micros: int = float('inf')) -> None:

        peer_node_health = self.get_current_peer_node_health(peer_wallet_address)

        # ('requests_sent', f_big_endian_int),
        # ('failed_requests', f_big_endian_int),
        # ('average_response_time', f_big_endian_int)  # milliseconds
        #

        new_requests_sent = peer_node_health.requests_sent + 1
        if response_time_in_micros == float('inf'):
            #it didn't respond
            new_failed_requests = peer_node_health.failed_requests + 1
            new_average_response_time = peer_node_health.average_response_time
        else:
            new_failed_requests = peer_node_health.failed_requests
            new_average_response_time = int(add_sample_to_average(peer_node_health.average_response_time, response_time_in_micros, new_requests_sent))

        validate_uint256(new_requests_sent, title="new_requests_sent")
        validate_uint256(new_failed_requests, title="new_failed_requests")
        validate_uint256(new_average_response_time, title="new_average_response_time")

        self.set_current_peer_node_health(peer_wallet_address, peer_node_health.copy(requests_sent = new_requests_sent,
                                                                                     failed_requests = new_failed_requests,
                                                                                     average_response_time = new_average_response_time))

        #save this time as the latest timestamp for save health request
        lookup_key = SchemaV1.make_latest_peer_node_health_timestamp_lookup_key()
        timestamp_rounded_peer_node_health_check = int(int(time.time()/(TIME_BETWEEN_PEER_NODE_HEALTH_CHECK))*(TIME_BETWEEN_PEER_NODE_HEALTH_CHECK))
        rlp_encoded = rlp.encode(timestamp_rounded_peer_node_health_check, sedes=rlp.sedes.f_big_endian_int)
        self.db[lookup_key] = rlp_encoded



    def get_timestamp_of_last_health_request(self) -> Timestamp:
        lookup_key = SchemaV1.make_latest_peer_node_health_timestamp_lookup_key()
        try:
            return rlp.decode(self.db[lookup_key], sedes=rlp.sedes.f_big_endian_int)
        except KeyError:
            return 0

    def get_signed_peer_score_string_private_key(self,
                                                 private_key_string: bytes,
                                                 network_id: int,
                                                  peer_wallet_address: Address,
                                                  after_block_number: BlockNumber = None,
                                                  ) -> NodeStakingScore:
        '''
        This is to allow other processes to use this function when being unable to pickle a PrivateKey
        :param private_key:
        :param peer_wallet_address:
        :param after_block_number:
        :return:
        '''

        private_key = keys.PrivateKey(private_key_string)
        return self.get_signed_peer_score(private_key,
                                          network_id,
                                          peer_wallet_address,
                                          after_block_number,
                                          )

    def get_signed_peer_score(self, private_key: PrivateKey,
                              network_id:int,
                              peer_wallet_address: Address,
                              after_block_number: BlockNumber = None,
                              ) -> NodeStakingScore:

        this_node_wallet_address = private_key.public_key.to_canonical_address()

        if after_block_number is None:
            after_block_number = self.chaindb.get_latest_reward_block_number(peer_wallet_address)

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


        head_hash_of_local_chain = self.chaindb.get_canonical_head_hash(this_node_wallet_address)
        node_staking_score = NodeStakingScore(peer_wallet_address,
                                              score,
                                              after_block_number,
                                              int(time.time()),
                                              head_hash_of_local_chain,
                                              v = 0,
                                              r = 0,
                                              s = 0)



        signed_node_staking_score = node_staking_score.get_signed(private_key, network_id)

        return signed_node_staking_score


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
    # Score creation and calculation
    #


    def calculate_reward_based_on_fractional_interest(self,  wallet_address: Address, fractional_interest: float, at_timestamp: Timestamp = None) -> int:
        '''
        Here we assume the time period for the reward starts from the latest reward block. This is a valid assumption
        because blocks can only be added to the top of the chain
        :param wallet_address:
        :param fractional_interest:
        :param at_timestamp:
        :return:
        '''
        validate_canonical_address(wallet_address, 'wallet_address')

        if at_timestamp is None:
            at_timestamp = int(time.time())

        latest_reward_block_number = self.chaindb.get_latest_reward_block_number(wallet_address)
        try:
            since_timestamp = self.chaindb.get_canonical_block_header_by_number(latest_reward_block_number,
                                                                                wallet_address).timestamp
        except HeaderNotFound:
            return 0

        canonical_head_block_number = self.chaindb.get_canonical_head(wallet_address).block_number

        # loop backwards to make things simpler
        calc_to_timestamp = at_timestamp
        amount = 0
        for current_block_number in range(canonical_head_block_number, latest_reward_block_number - 1, -1):
            header = self.chaindb.get_canonical_block_header_by_number(BlockNumber(current_block_number), wallet_address)

            header_mature_timestamp = header.timestamp + COIN_MATURE_TIME_FOR_STAKING
            # this finds the start of the calculation
            if header_mature_timestamp >= calc_to_timestamp:
                continue

            # this finds the end of the calculation
            if header_mature_timestamp <= since_timestamp:
                break

            time_difference = calc_to_timestamp - header_mature_timestamp

            calc_stake = header.account_balance

            amount += time_difference * calc_stake * fractional_interest

            calc_to_timestamp = header_mature_timestamp

        # if we are calculating all the way to the genesis block, there will be a small
        # COIN_MATURE_TIME_FOR_STAKING that we missed. however, this window has 0 stake, so it would add nothing

        return int(amount)


    def calculate_final_reward_type_2_amount(self, node_staking_score_list: List[NodeStakingScore], at_timestamp: Timestamp = None) -> Tuple[int, List[NodeStakingScore]]:
        '''
        This automatically calculates the highest possible score based on the node_staking_scores provided
        :param node_staking_score_list:
        :return:
        '''

        node_staking_score_list = list(node_staking_score_list)

        if at_timestamp is None:
            at_timestamp = int(time.time())

        wallet_address = node_staking_score_list[0].recipient_node_wallet_address
        node_staking_score_list.sort(key=lambda x: -1*x.score)

        total_stake = 0
        num_proofs = 0
        final_list = []
        item_stake_list = []
        for node_staking_score in node_staking_score_list:
            stake = self.chaindb.get_mature_stake(node_staking_score.sender, timestamp = node_staking_score.timestamp)
            final_list.append(node_staking_score)
            item_stake_list.append((node_staking_score.score, stake))

            total_stake += stake
            num_proofs += 1

            if total_stake >= REQUIRED_STAKE_FOR_REWARD_TYPE_2_PROOF and num_proofs >= REQUIRED_NUMBER_OF_PROOFS_FOR_REWARD_TYPE_2_PROOF:
                break

        if total_stake < REQUIRED_STAKE_FOR_REWARD_TYPE_2_PROOF or num_proofs < REQUIRED_NUMBER_OF_PROOFS_FOR_REWARD_TYPE_2_PROOF:
            raise NotEnoughProofsOrStakeForRewardType2Proof()

        final_score = int(stake_weighted_average(item_stake_list))


        fractional_interest = REWARD_TYPE_2_AMOUNT_FACTOR * final_score / 1000000

        amount = self.calculate_reward_based_on_fractional_interest(wallet_address, fractional_interest, at_timestamp)
        if amount != 0:
            return amount, final_list
        else:
            return 0, []

    def calculate_final_reward_type_1_amount(self, wallet_address: Address, at_timestamp: Timestamp = None) -> int:
        '''
        :param wallet_address:
        :return:
        '''

        validate_canonical_address(wallet_address, 'wallet_address')

        if at_timestamp == None:
            at_timestamp = int(time.time())

        fractional_interest = REWARD_TYPE_1_AMOUNT_FACTOR

        amount = self.calculate_reward_based_on_fractional_interest(wallet_address, fractional_interest, at_timestamp)

        return amount



    #
    # Reward creation and verification
    #

    def create_reward_bundle_for_block(self,
                                       wallet_address: Address,
                                       node_staking_score_list: List[NodeStakingScore] = None,
                                       at_timestamp: Timestamp = None) -> StakeRewardBundle:

        wallet_address = wallet_address

        reward_type_1_amount = self.calculate_final_reward_type_1_amount(wallet_address, at_timestamp)
        reward_type_1 = StakeRewardType1(reward_type_1_amount)

        if node_staking_score_list is not None:
            reward_type_2_amount, proof_list = self.calculate_final_reward_type_2_amount(node_staking_score_list,at_timestamp)
        else:
            reward_type_2_amount, proof_list = 0, []

        reward_type_2 = StakeRewardType2(reward_type_2_amount, proof_list)

        reward_bundle = StakeRewardBundle(reward_type_1, reward_type_2)

        return reward_bundle

    def validate_node_staking_score(self, node_staking_score: NodeStakingScore, since_block_number: BlockNumber) -> None:
        node_staking_score.validate()

        # make sure all proof's have valid signatures
        node_staking_score.check_signature_validity()

        # need to make sure we have the up-to-date peer chain so that our stake calculation is correct.
        # RewardProofSenderBlockMissing
        if not self.chaindb.is_in_canonical_chain(node_staking_score.head_hash_of_sender_chain):
            raise RewardProofSenderBlockMissing("Our chain for chain_address {} appears to be out of date. We need the block with hash {}".format(
                encode_hex(node_staking_score.sender), encode_hex(node_staking_score.head_hash_of_sender_chain)))

        # We need to validate that the previous reward block in proof equals the latest reward block
        if node_staking_score.since_block_number != since_block_number:
            raise ValidationError("Reward proof has incorrect since_block_number. Got {}, but should be {}".format(
                node_staking_score.since_block_number,
                since_block_number))

        if node_staking_score.score < 0 or node_staking_score.score > 1000000:
            raise ValidationError(
                'Node staking score is out of allowed range of 0 to 1,000,000. Got {}'.format(node_staking_score.score))

    def validate_node_staking_score_with_context(self, node_staking_score: NodeStakingScore, chain_address: Address, block_timestamp: Timestamp, latest_reward_block_number: BlockNumber) -> None:

        if (node_staking_score.timestamp > (block_timestamp + REWARD_PROOF_TIMESTAMP_VARIABILITY_ALLOWANCE)
                or node_staking_score.timestamp < (block_timestamp - REWARD_PROOF_TIMESTAMP_VARIABILITY_ALLOWANCE)):
            raise ValidationError('Reward type 2 proof isnt within acceptable range of block timestamp')

        # make sure recipient node wlalet address is this node
        if node_staking_score.recipient_node_wallet_address != chain_address:
            raise ValidationError("Reward type 2 proof recipient_node_wallet_address doesnt match this chain address")

        #make sure the node_staking_score isnt from the same node trying to recieve the reward
        if node_staking_score.sender == chain_address:
            raise ValidationError(
                'One of the reward proofs was generated by the node receiving the reward. It needs proof from other nodes.')

        self.validate_node_staking_score(node_staking_score, since_block_number = latest_reward_block_number)


    def validate_reward_bundle(self, reward_bundle:StakeRewardBundle, chain_address:Address, block_timestamp: Timestamp) -> None:

        latest_reward_block_number = self.chaindb.get_latest_reward_block_number(chain_address)
        latest_reward_block_timestamp = self.chaindb.get_canonical_block_header_by_number(latest_reward_block_number, chain_address).timestamp

        # need to check to make sure it has been long enough since the last reward block.
        if block_timestamp - latest_reward_block_timestamp < MIN_ALLOWED_TIME_BETWEEN_REWARD_BLOCKS:
            raise ValidationError("Not enough time between reward blocks. Got {}, expected {}".format((block_timestamp - latest_reward_block_timestamp),
                                                                                                      MIN_ALLOWED_TIME_BETWEEN_REWARD_BLOCKS))


        #first we validate reward type 1. All reward bundles must contain this.
        #we have to allow a bit of time difference allowance because the node can calculate this amount just before it sets the block timestamp
        reward_type_1_max_amount = self.calculate_final_reward_type_1_amount(chain_address, block_timestamp + REWARD_BLOCK_AND_BUNDLE_TIMESTAMP_VARIABILITY_ALLOWANCE)
        reward_type_1_min_amount = self.calculate_final_reward_type_1_amount(chain_address, block_timestamp - REWARD_BLOCK_AND_BUNDLE_TIMESTAMP_VARIABILITY_ALLOWANCE)

        if reward_bundle.reward_type_1.amount > reward_type_1_max_amount or reward_bundle.reward_type_1.amount < reward_type_1_min_amount:
            raise ValidationError("Reward type 1 amount is not within the allowed range. Allowed from {} to {} but got {}".format(reward_type_1_min_amount,
                                                                                                                                  reward_type_1_max_amount,
                                                                                                                                  reward_bundle.reward_type_1.amount))


        #next we validate reward type 2. Only some bundles will contain this.
        if reward_bundle.reward_type_2.amount != 0:
            # need to create function that validates the reward.
            # check timestamps are all near the block timestamp. leave wiggle room for network latency
            for node_staking_score in reward_bundle.reward_type_2.proof:
                self.validate_node_staking_score_with_context(node_staking_score,
                                                              chain_address = chain_address,
                                                              block_timestamp = block_timestamp,
                                                              latest_reward_block_number = latest_reward_block_number)

            #These functions will check for minimum required stake, and minimum number of proofs.
            reward_type_2_max_amount, proof_list = self.calculate_final_reward_type_2_amount(list(reward_bundle.reward_type_2.proof),
                                                                                 block_timestamp + REWARD_BLOCK_AND_BUNDLE_TIMESTAMP_VARIABILITY_ALLOWANCE)
            reward_type_2_min_amount, _ = self.calculate_final_reward_type_2_amount(list(reward_bundle.reward_type_2.proof),
                                                                                 block_timestamp - REWARD_BLOCK_AND_BUNDLE_TIMESTAMP_VARIABILITY_ALLOWANCE)

            #make sure they aren't including more proof then nessisary
            if len(proof_list) != len(reward_bundle.reward_type_2.proof):
                raise ValidationError("The reward type 2 contains to many entries for proof. Expected {}, but got {}.".format(len(proof_list), len(reward_bundle.reward_type_2.proof)))


            if reward_bundle.reward_type_2.amount > reward_type_2_max_amount or reward_bundle.reward_type_2.amount < reward_type_2_min_amount:
                raise ValidationError(
                    "Reward type 2 amount is not within the allowed range. Allowed from {} to {} but got {}".format(
                        reward_type_2_min_amount,
                        reward_type_2_max_amount,
                        reward_bundle.reward_type_2.amount))
        else:
            #if the value is 0, lets make sure there are no proofs
            if len(reward_bundle.reward_type_2.proof) > 0:
                raise ValidationError("Reward type 2 has a value of 0, but there is proof given. Don't need proof if there is no amount.")




    #
    # Helpers for Internal
    #
    def get_current_peer_node_health(self,peer_wallet_address: Address) -> PeerNodeHealth:
        after_block_number = self.chaindb.get_latest_reward_block_number(peer_wallet_address)
        return self._get_peer_node_health(peer_wallet_address, after_block_number)

    def set_current_peer_node_health(self,peer_wallet_address: Address,  peer_node_health: PeerNodeHealth) -> None:
        after_block_number = self.chaindb.get_latest_reward_block_number(peer_wallet_address)
        self._set_peer_node_health(peer_wallet_address, after_block_number, peer_node_health)

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

 

    
  



        
    
    
    
    
    
    
    
    
    
    