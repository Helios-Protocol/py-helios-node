from decimal import Decimal

from eth_utils import to_wei

from hvm.vm.forks.boson.consensus import BosonConsensusDB

REWARD_TYPE_1_AMOUNT_FACTOR = 0 #1 % per year
REWARD_TYPE_2_AMOUNT_FACTOR = Decimal(0.03*1/(60*60*24*365)) #3 % per year for normal nodes

MASTERNODE_LEVEL_1_REQUIRED_BALANCE = to_wei(10000, 'ether')
MASTERNODE_LEVEL_2_REQUIRED_BALANCE = to_wei(75000, 'ether')
MASTERNODE_LEVEL_3_REQUIRED_BALANCE = to_wei(150000, 'ether')

MASTERNODE_LEVEL_1_REWARD_TYPE_2_MULTIPLIER = Decimal(4/3) #4 % per year
MASTERNODE_LEVEL_2_REWARD_TYPE_2_MULTIPLIER = Decimal(6/3) #6 % per year
MASTERNODE_LEVEL_3_REWARD_TYPE_2_MULTIPLIER = Decimal(8/3) #8 % per year

EARLY_BIRD_BONUS_FACTOR = 5 #5 x rewards for the first year
EARLY_BIRD_BONUS_CUTOFF_TIMESTAMP = 1593505425 # Tuesday, June 30, 2020 1:23:45 AM GMT-07:00


TIME_BETWEEN_PEER_NODE_HEALTH_CHECK = 60 * 60  # check the health of connected peers once per hour
MIN_ALLOWED_TIME_BETWEEN_REWARD_BLOCKS = 60*60*24 # once per day
REWARD_BLOCK_CREATION_ATTEMPT_FREQUENCY = 60*30 # retry making a reward block every 30 minutes
REWARD_PROOF_TIMESTAMP_VARIABILITY_ALLOWANCE = 300
REQUIRED_STAKE_FOR_REWARD_TYPE_2_PROOF = MASTERNODE_LEVEL_3_REQUIRED_BALANCE*2
REQUIRED_NUMBER_OF_PROOFS_FOR_REWARD_TYPE_2_PROOF = 2
COIN_MATURE_TIME_FOR_STAKING = 60*60*72 # 72 hours
PEER_NODE_HEALTH_CHECK_RESPONSE_TIME_PENALTY_START_MS = 100 #this is the average response time where the staking score starts to be reduced.
PEER_NODE_HEALTH_CHECK_RESPONSE_TIME_PENALTY_50_PERCENT_REDUCTION_MS = 500 #this is the response time in ms where the staking score is reduced by 50%


class PhotonConsensusDB(BosonConsensusDB):
    reward_type_1_amount_factor = REWARD_TYPE_1_AMOUNT_FACTOR
    reward_type_2_amount_factor = REWARD_TYPE_2_AMOUNT_FACTOR

    masternode_level_3_required_balance = MASTERNODE_LEVEL_3_REQUIRED_BALANCE
    masternode_level_3_multiplier = MASTERNODE_LEVEL_3_REWARD_TYPE_2_MULTIPLIER
    masternode_level_2_required_balance = MASTERNODE_LEVEL_2_REQUIRED_BALANCE
    masternode_level_2_multiplier = MASTERNODE_LEVEL_2_REWARD_TYPE_2_MULTIPLIER
    masternode_level_1_required_balance = MASTERNODE_LEVEL_1_REQUIRED_BALANCE
    masternode_level_1_multiplier = MASTERNODE_LEVEL_1_REWARD_TYPE_2_MULTIPLIER

    peer_node_health_check_response_time_penalty_start_ms = PEER_NODE_HEALTH_CHECK_RESPONSE_TIME_PENALTY_START_MS  # this is the average response time where the staking score starts to be reduced.
    peer_node_health_check_response_time_penalty_50_percent_reduction_ms = PEER_NODE_HEALTH_CHECK_RESPONSE_TIME_PENALTY_50_PERCENT_REDUCTION_MS  # this is the response time in ms where the staking score is reduced by 50%
    time_between_peer_node_health_check = TIME_BETWEEN_PEER_NODE_HEALTH_CHECK # check the health of connected peers once per hour
    min_time_between_reward_blocks = MIN_ALLOWED_TIME_BETWEEN_REWARD_BLOCKS # once per day
    reward_proof_timestamp_variability_allowance = REWARD_PROOF_TIMESTAMP_VARIABILITY_ALLOWANCE
    reward_block_creation_attempt_frequency = REWARD_BLOCK_CREATION_ATTEMPT_FREQUENCY # retry making a reward block every 30 minutes
    required_stake_for_reward_type_2_proof = REQUIRED_STAKE_FOR_REWARD_TYPE_2_PROOF
    required_number_of_proofs_for_reward_type_2_proof = REQUIRED_NUMBER_OF_PROOFS_FOR_REWARD_TYPE_2_PROOF
    coin_mature_time_for_staking = COIN_MATURE_TIME_FOR_STAKING # 72 hours


