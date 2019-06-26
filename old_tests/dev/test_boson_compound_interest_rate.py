# from eth_keys import keys
# import json
# from hvm.constants import TESTNET_FAUCET_PRIVATE_KEY
# from hvm.constants import random_private_keys
# print(keys.PrivateKey(TESTNET_FAUCET_PRIVATE_KEY).public_key.to_address())

# from helios.rlp_templates.hls import (
#     BlockHashKey)

from decimal import Decimal
REWARD_TYPE_1_AMOUNT_FACTOR = 0 #1 % per year
REWARD_TYPE_2_AMOUNT_FACTOR = Decimal(0.03*1/(60*60*24*365)) #3 % per year for normal nodes

MASTERNODE_LEVEL_1_REWARD_TYPE_2_MULTIPLIER = Decimal(4/3) #5 % per year
MASTERNODE_LEVEL_2_REWARD_TYPE_2_MULTIPLIER = Decimal(6/3) #7 % per year
MASTERNODE_LEVEL_3_REWARD_TYPE_2_MULTIPLIER = Decimal(8/3) #9 % per year

EARLY_BIRD_BONUS_FACTOR = 5 #6 x rewards for the first year

normal_node_fractional_interest = REWARD_TYPE_2_AMOUNT_FACTOR
masternode_level_1_fractional_interest = REWARD_TYPE_2_AMOUNT_FACTOR*MASTERNODE_LEVEL_1_REWARD_TYPE_2_MULTIPLIER
masternode_level_2_fractional_interest = REWARD_TYPE_2_AMOUNT_FACTOR*MASTERNODE_LEVEL_2_REWARD_TYPE_2_MULTIPLIER
masternode_level_3_fractional_interest = REWARD_TYPE_2_AMOUNT_FACTOR*MASTERNODE_LEVEL_3_REWARD_TYPE_2_MULTIPLIER


one_year_in_seconds = 60*60*24*365
min_time_between_reward_blocks = (60*60*24) #daily


current_fractional_interest = normal_node_fractional_interest
print("normal node original interest rate {}".format(round((current_fractional_interest*one_year_in_seconds),2)))
maximum_compound_interest = 1*((1+current_fractional_interest*min_time_between_reward_blocks))**(int(one_year_in_seconds/min_time_between_reward_blocks))
print("normal node compound interest rate {}".format(round((maximum_compound_interest-1), 2)))
print()

current_fractional_interest = masternode_level_1_fractional_interest
print("Masternode 1 original interest rate {}".format(round((current_fractional_interest*one_year_in_seconds),2)))
maximum_compound_interest = 1*((1+current_fractional_interest*min_time_between_reward_blocks))**(int(one_year_in_seconds/min_time_between_reward_blocks))
print("Masternode 1 compound interest rate {}".format(round((maximum_compound_interest-1), 2)))
print()

current_fractional_interest = masternode_level_2_fractional_interest
print("Masternode 2 original interest rate {}".format(round((current_fractional_interest*one_year_in_seconds),2)))
maximum_compound_interest = 1*((1+current_fractional_interest*min_time_between_reward_blocks))**(int(one_year_in_seconds/min_time_between_reward_blocks))
print("Masternode 2 compound interest rate {}".format(round((maximum_compound_interest-1), 2)))
print()

current_fractional_interest = masternode_level_3_fractional_interest
print("Masternode 3 original interest rate {}".format(round((current_fractional_interest*one_year_in_seconds),2)))
maximum_compound_interest = 1*((1+current_fractional_interest*min_time_between_reward_blocks))**(int(one_year_in_seconds/min_time_between_reward_blocks))
print("Masternode 3 compound interest rate {}".format(round((maximum_compound_interest-1), 2)))
print()



print("for first year:")
normal_node_fractional_interest = normal_node_fractional_interest*EARLY_BIRD_BONUS_FACTOR
masternode_level_1_fractional_interest = masternode_level_1_fractional_interest*EARLY_BIRD_BONUS_FACTOR
masternode_level_2_fractional_interest = masternode_level_2_fractional_interest*EARLY_BIRD_BONUS_FACTOR
masternode_level_3_fractional_interest = masternode_level_3_fractional_interest*EARLY_BIRD_BONUS_FACTOR

current_fractional_interest = normal_node_fractional_interest
print("normal node original interest rate {}".format(round((current_fractional_interest*one_year_in_seconds),2)))
maximum_compound_interest = 1*((1+current_fractional_interest*min_time_between_reward_blocks))**(int(one_year_in_seconds/min_time_between_reward_blocks))
print("normal node compound interest rate {}".format(round((maximum_compound_interest-1), 2)))
print()

current_fractional_interest = masternode_level_1_fractional_interest
print("Masternode 1 original interest rate {}".format(round((current_fractional_interest*one_year_in_seconds),2)))
maximum_compound_interest = 1*((1+current_fractional_interest*min_time_between_reward_blocks))**(int(one_year_in_seconds/min_time_between_reward_blocks))
print("Masternode 1 compound interest rate {}".format(round((maximum_compound_interest-1), 2)))
print()

current_fractional_interest = masternode_level_2_fractional_interest
print("Masternode 2 original interest rate {}".format(round((current_fractional_interest*one_year_in_seconds),2)))
maximum_compound_interest = 1*((1+current_fractional_interest*min_time_between_reward_blocks))**(int(one_year_in_seconds/min_time_between_reward_blocks))
print("Masternode 2 compound interest rate {}".format(round((maximum_compound_interest-1), 2)))
print()

current_fractional_interest = masternode_level_3_fractional_interest
print("Masternode 3 original interest rate {}".format(round((current_fractional_interest*one_year_in_seconds),2)))
maximum_compound_interest = 1*((1+current_fractional_interest*min_time_between_reward_blocks))**(int(one_year_in_seconds/min_time_between_reward_blocks))
print("Masternode 3 compound interest rate {}".format(round((maximum_compound_interest-1), 2)))
print()



