from hvm.db.consensus import ConsensusDB
from decimal import Decimal

PEER_NODE_HEALTH_CHECK_RESPONSE_TIME_PENALTY_START_MS = 100 #this is the average response time where the staking score starts to be reduced.

REWARD_TYPE_1_AMOUNT_FACTOR = Decimal(0.02*1/(60*60*24*365)) #2 % per year
REWARD_TYPE_2_AMOUNT_FACTOR = Decimal(0.1*1/(60*60*24*365)) #10 % per year for normal nodes

HELIOS_TESTNET_REWARD_TYPE_1_AMOUNT_FACTOR = REWARD_TYPE_1_AMOUNT_FACTOR
HELIOS_TESTNET_REWARD_TYPE_2_AMOUNT_FACTOR = REWARD_TYPE_2_AMOUNT_FACTOR

TIME_BETWEEN_PEER_NODE_HEALTH_CHECK = 5
MIN_ALLOWED_TIME_BETWEEN_REWARD_BLOCKS = 1
REWARD_PROOF_TIMESTAMP_VARIABILITY_ALLOWANCE = 300
REWARD_BLOCK_CREATION_ATTEMPT_FREQUENCY = 5
REQUIRED_STAKE_FOR_REWARD_TYPE_2_PROOF = 100
REQUIRED_NUMBER_OF_PROOFS_FOR_REWARD_TYPE_2_PROOF = 1
COIN_MATURE_TIME_FOR_STAKING = 1

class HeliosTestnetConsensusDB(ConsensusDB):
    reward_type_1_amount_factor = HELIOS_TESTNET_REWARD_TYPE_1_AMOUNT_FACTOR
    reward_type_2_amount_factor = HELIOS_TESTNET_REWARD_TYPE_2_AMOUNT_FACTOR
    time_between_peer_node_health_check = TIME_BETWEEN_PEER_NODE_HEALTH_CHECK

    peer_node_health_check_response_time_penalty_start_ms = PEER_NODE_HEALTH_CHECK_RESPONSE_TIME_PENALTY_START_MS
    peer_node_health_check_response_time_penalty_50_percent_reduction_ms = 1000

    min_time_between_reward_blocks = MIN_ALLOWED_TIME_BETWEEN_REWARD_BLOCKS
    reward_proof_timestamp_variability_allowance = REWARD_PROOF_TIMESTAMP_VARIABILITY_ALLOWANCE
    reward_block_creation_attempt_frequency = REWARD_BLOCK_CREATION_ATTEMPT_FREQUENCY
    required_stake_for_reward_type_2_proof = REQUIRED_STAKE_FOR_REWARD_TYPE_2_PROOF
    required_number_of_proofs_for_reward_type_2_proof = REQUIRED_NUMBER_OF_PROOFS_FOR_REWARD_TYPE_2_PROOF
    coin_mature_time_for_staking = COIN_MATURE_TIME_FOR_STAKING

    def calculate_node_staking_score(self, requests_sent: int, failed_requests: int, average_response_time: int, time_since_last_reward) -> int:
        '''
        # This function is broken. Just leaving it here for this fork so we don't have to reset the blockchain database
        returns a score out of 1,000,000. Increased resolution to 1 million so that nodes that go for a very long time without getting their reward dont average to 0.
        This uses a f = A/(x+A) function to calculate score lost to response time.
        Also bases the score on the percentage of time since last reward that the node was online.
        :param requests_sent:
        :param failed_requests:
        :param average_response_time: (in microseconds)
        :return:
        '''


        uptime = (requests_sent - failed_requests) * self.time_between_peer_node_health_check

        uptime_multiplier = uptime/time_since_last_reward

        average_response_time_past_pentalty_start = average_response_time - self.peer_node_health_check_response_time_penalty_start_ms
        if average_response_time_past_pentalty_start < 0:
            average_response_time_past_pentalty_start = 0

        response_time_multiplier = ((self.peer_node_health_check_response_time_penalty_50_percent_reduction_ms-self.peer_node_health_check_response_time_penalty_start_ms)/
                                    (average_response_time_past_pentalty_start+
                                     self.peer_node_health_check_response_time_penalty_50_percent_reduction_ms-
                                     self.peer_node_health_check_response_time_penalty_start_ms))

        score = int(uptime_multiplier*response_time_multiplier*1000000)

        if score < 0:
            score = 0

        return score