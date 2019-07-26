import logging
import os
import random
import time
import sys
from pprint import pprint


from hvm import constants

from hvm import TestnetChain
from hvm.chains.testnet import (
    TESTNET_GENESIS_PARAMS,
    TESTNET_GENESIS_STATE,
    TESTNET_GENESIS_PRIVATE_KEY,
    TESTNET_NETWORK_ID,
)

from hvm.constants import (
    GAS_TX)

from hvm.vm.forks.boson.constants import MIN_TIME_BETWEEN_BLOCKS
from hvm.db.backends.level import LevelDB
from hvm.db.backends.memory import MemoryDB
from hvm.db.journal import (
    JournalDB,
)

from hvm.db.chain import ChainDB
from hvm.db.trie import make_trie_root_and_nodes
from hvm.rlp.headers import MicroBlockHeader
from hvm.rlp.transactions import BaseTransaction

import rlp as rlp


from eth_utils import (
    encode_hex,
    decode_hex,
)
from helios.dev_tools import create_dev_test_random_blockchain_database, \
    create_dev_test_blockchain_database_with_given_transactions, create_new_genesis_params_and_state, \
    add_transactions_to_blockchain_db
from eth_keys import keys
from sys import exit

from trie import (
    HexaryTrie,
)
from hvm.db.hash_trie import HashTrie

import matplotlib.pyplot as plt

from hvm.db.chain_head import ChainHeadDB

from eth_utils import (
    int_to_big_endian,
    big_endian_to_int,
)
from eth_keys import keys

from eth_keys.datatypes import(
        BaseKey,
        PublicKey,
        PrivateKey
)

from hvm.vm.forks.boson.consensus import(
    MASTERNODE_LEVEL_3_REQUIRED_BALANCE,
    MASTERNODE_LEVEL_3_REWARD_TYPE_2_MULTIPLIER,
    MASTERNODE_LEVEL_2_REQUIRED_BALANCE,
    MASTERNODE_LEVEL_2_REWARD_TYPE_2_MULTIPLIER,
    MASTERNODE_LEVEL_1_REQUIRED_BALANCE,
    MASTERNODE_LEVEL_1_REWARD_TYPE_2_MULTIPLIER,
    REWARD_TYPE_2_AMOUNT_FACTOR,
    EARLY_BIRD_BONUS_FACTOR,
    EARLY_BIRD_BONUS_CUTOFF_TIMESTAMP
)


# import matplotlib.pyplot as plt

from hvm.utils.profile import profile

#for testing purposes we will just have the primary private key hardcoded
#TODO: save to encrypted json file
#primary_private_keys = [b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5', b'\xa41\x95@\xbb\xa5\xde\xbbc\xffR\x8a\x18\x06\x95\xa3\xd7\xd2\x95]5{\x12\xe4n\xb6R\xd7S\x96\xf0+', b'\xd8>Fh\xefT\x04jf\x13\xca|E\xc4\x91\xed\x07\xcd\x02fW\xd8s;\xd8\xe4\xde\xb9\xbc\xe4\xf0I', b'\x83\x1d\xf6\xaf-\x00\xbfS4\x0f\xcds\x18"\xdd\x906]e\xfc\xe6\x0c?\xb1v20\xced7y\xf4', b")M\xf4\x1c\xb7\xe0Z\xf4\x17F\x9b\x089'\x004\xd3\x89\xd8\x80\xf5`\xa2\x11\x00\x90\xbd\x0f&KjZ", b'RI\xda\xbc7\xc4\xe8\tz\xfaI\x1f\xa1\x02{v\x0e\xac\x87W\xa2s\x81L4M\xad\xbd\xb3\x84\xaae', b'>kG\xd5\xb3qG\x84\xa6"\x1c~\xb6\xbf\x96\xac\n\x88\xfb\x05\x8aG\r\xe9Z\x16\x15\xb1P\xe0\xb7[', b'\x87\xf6\xb1\xa7v\x8bv<\xa3\xe5\xb18\xa7u\x99\xbaBa\xe9\xd5\x0e\xcb\x0f?\x84nZ\xba\xdf\xa3\x8a~', b'`$g\xe9\xa5r\xd2\xacG&\xf81^\x98\xf7\xda\xa5\xf4\x93)\xf3\x0c\x18\x84\xe4)!\x9dR\xa0\xac\xd3', b'\xcfd\xd5|\xe2\xf1\xda\xb9\x1f|\xb9\xdc\xeb \xd7\xb0\x81g\xdc\x03\xd6dQ\xf14\x19`\x94o\xf7\xc7\x1b', b'}LO\x14($d\n!\x1a\x91\xa8S\xb3\x05\xaa\x89\xf2\x0b\x97\xd3\x1c#\xe7\x86g`\xf1\x1a\xedXW']
from hvm.constants import random_private_keys
from hvm.vm.forks.helios_testnet.blocks import HeliosMicroBlock, HeliosTestnetBlock

def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(random_private_keys[instance_number])

SENDER = TESTNET_GENESIS_PRIVATE_KEY
RECEIVER = get_primary_node_private_helios_key(1)
RECEIVER2 = get_primary_node_private_helios_key(2)
RECEIVER3 = get_primary_node_private_helios_key(3)
RECEIVER4 = get_primary_node_private_helios_key(4)


def test_boson_vm_calculate_node_staking_score():
    from hvm.vm.forks.boson.consensus import TIME_BETWEEN_PEER_NODE_HEALTH_CHECK

    testdb = MemoryDB()
    sender_chain = TestnetChain.from_genesis(testdb, SENDER.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS,TESTNET_GENESIS_STATE)

    boson_fork_timestamp = 0
    for timestamp_vm_config in TestnetChain.vm_configuration:
        if timestamp_vm_config[1].fork == 'boson':
            boson_fork_timestamp = timestamp_vm_config[0]


    boson_vm = sender_chain.get_vm(timestamp = boson_fork_timestamp)

    consensus_db = boson_vm.consensus_db

    #
    # score vs latency
    #
    latency = []
    staking_score = []
    for current_latency in range(1000, 1000000, 100000):
        current_staking_score = consensus_db.calculate_node_staking_score(average_response_time= current_latency,
                                                                  failed_requests = 0,
                                                                  requests_sent= 100,
                                                                  time_since_last_reward= TIME_BETWEEN_PEER_NODE_HEALTH_CHECK*100)
        latency.append(current_latency/1000)
        staking_score.append(current_staking_score/10000)


    print(staking_score)
    print(latency)

    plt.plot(latency, staking_score)
    plt.xlabel('Latency (ms)')
    plt.ylabel('Percentage of max stake')

    plt.savefig('plots/staking_score_vs_latency.png', bbox_inches='tight')
    plt.clf()

    #
    # score vs failed requests
    #
    failed_requests = []
    staking_score = []
    for current_failed_requests in range(0,100, 5):
        current_staking_score = consensus_db.calculate_node_staking_score(average_response_time=100000,
                                                                          failed_requests=current_failed_requests,
                                                                          requests_sent=100,
                                                                          time_since_last_reward=TIME_BETWEEN_PEER_NODE_HEALTH_CHECK * 100)
        failed_requests.append(current_failed_requests)
        staking_score.append(current_staking_score/10000)

    print(failed_requests)
    print(staking_score)

    plt.plot(failed_requests, staking_score)
    plt.xlabel('Failed requests (% of requests sent)')
    plt.ylabel('Percentage of max stake')

    plt.savefig('plots/staking_score_vs_failed_requests.png', bbox_inches='tight')
    plt.clf()

    #
    # score vs percentage of uptime
    #
    percentage_of_uptime = []
    staking_score = []
    start = TIME_BETWEEN_PEER_NODE_HEALTH_CHECK * 10
    for current_time_since_last_reward in range(start, start + start*100, start):
        current_staking_score = consensus_db.calculate_node_staking_score(average_response_time=100000,
                                                                          failed_requests=0,
                                                                          requests_sent=10,
                                                                          time_since_last_reward=current_time_since_last_reward)
        percentage_of_uptime.append(start/current_time_since_last_reward)
        staking_score.append(current_staking_score/10000)

    print(percentage_of_uptime)
    print(staking_score)

    plt.plot(percentage_of_uptime, staking_score)
    plt.xlabel('Percentage of uptime')
    plt.ylabel('Percentage of max stake')

    plt.savefig('plots/staking_score_vs_time_since_last_reward.png', bbox_inches='tight')
    plt.clf()

# test_boson_vm_calculate_node_staking_score()
# exit()

def test_boson_vm_calculate_reward_based_on_fractional_interest():
    testdb = MemoryDB()

    masternode_level_3_required_balance = MASTERNODE_LEVEL_3_REQUIRED_BALANCE
    masternode_level_3_multiplier = MASTERNODE_LEVEL_3_REWARD_TYPE_2_MULTIPLIER
    masternode_level_2_required_balance = MASTERNODE_LEVEL_2_REQUIRED_BALANCE
    masternode_level_2_multiplier = MASTERNODE_LEVEL_2_REWARD_TYPE_2_MULTIPLIER
    masternode_level_1_required_balance = MASTERNODE_LEVEL_1_REQUIRED_BALANCE
    masternode_level_1_multiplier = MASTERNODE_LEVEL_1_REWARD_TYPE_2_MULTIPLIER

    genesis_block_time = int(time.time())-10000000
    genesis_params, genesis_state = create_new_genesis_params_and_state(TESTNET_GENESIS_PRIVATE_KEY, masternode_level_3_required_balance * 2, genesis_block_time)

    time_between_blocks = max(MIN_TIME_BETWEEN_BLOCKS, 1)
    # import genesis block
    TestnetChain.from_genesis(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), genesis_params, genesis_state)

    stake_start = genesis_block_time+time_between_blocks
    tx_list = [[TESTNET_GENESIS_PRIVATE_KEY, RECEIVER, masternode_level_3_required_balance, stake_start],
               [RECEIVER, RECEIVER2, (masternode_level_3_required_balance-masternode_level_2_required_balance-GAS_TX), stake_start+100000],
               [RECEIVER, RECEIVER2, (masternode_level_2_required_balance-masternode_level_1_required_balance-GAS_TX), stake_start+200000],
               [RECEIVER, RECEIVER2, (masternode_level_1_required_balance-1000000-GAS_TX), stake_start+300000]]

    add_transactions_to_blockchain_db(testdb, tx_list)


    receiver_chain = TestnetChain(testdb, RECEIVER.public_key.to_canonical_address(), RECEIVER)

    fractional_interest = REWARD_TYPE_2_AMOUNT_FACTOR

    boson_fork_timestamp = 0
    for timestamp_vm_config in TestnetChain.vm_configuration:
        if timestamp_vm_config[1].fork == 'boson':
            boson_fork_timestamp = timestamp_vm_config[0]

    boson_vm = receiver_chain.get_vm(timestamp=boson_fork_timestamp)

    consensus_db = boson_vm.consensus_db

    calculate_at_timestamp = int(time.time())
    reward = consensus_db.calculate_reward_based_on_fractional_interest(RECEIVER.public_key.to_canonical_address(), fractional_interest, calculate_at_timestamp)

    if calculate_at_timestamp < EARLY_BIRD_BONUS_CUTOFF_TIMESTAMP:
        early_bird_bonus = EARLY_BIRD_BONUS_FACTOR
    else:
        early_bird_bonus = 1
    expected_reward_part_1 = fractional_interest*early_bird_bonus*(masternode_level_3_required_balance*100000*masternode_level_3_multiplier)
    expected_reward_part_2 = fractional_interest*early_bird_bonus*(masternode_level_2_required_balance*100000*masternode_level_2_multiplier)
    expected_reward_part_3 = fractional_interest*early_bird_bonus*(masternode_level_1_required_balance*100000*masternode_level_1_multiplier)
    expected_reward_part_4 = fractional_interest*early_bird_bonus*(1000000)*(calculate_at_timestamp-(stake_start+300000)-consensus_db.coin_mature_time_for_staking)
    
    # print("Expected calculation = {} * {} * {} * {}".format((calculate_at_timestamp-(stake_start+300000)-COIN_MATURE_TIME_FOR_STAKING), 1000000, fractional_interest, 1))
    # print("Expected calculation = {} * {} * {} * {}".format(100000, masternode_level_1_required_balance, fractional_interest, masternode_level_1_multiplier))
    # print("Expected calculation = {} * {} * {} * {}".format(100000, masternode_level_2_required_balance, fractional_interest, masternode_level_2_multiplier))
    # print("Expected calculation = {} * {} * {} * {}".format(100000, masternode_level_3_required_balance, fractional_interest, masternode_level_3_multiplier))
    #
    # print("Expected reward {}".format(int(expected_reward_part_4)))
    # print("Expected reward {}".format(int(expected_reward_part_4)+int(expected_reward_part_3)))
    # print("Expected reward {}".format(int(expected_reward_part_4)+int(expected_reward_part_3)+int(expected_reward_part_2)))
    # print("Expected reward {}".format(int(expected_reward_part_4)+int(expected_reward_part_3)+int(expected_reward_part_2)+int(expected_reward_part_1)))

    expected_reward = int(expected_reward_part_1) + int(expected_reward_part_2) + int(expected_reward_part_3) + int(expected_reward_part_4)
    assert(reward == expected_reward)

# test_boson_vm_calculate_reward_based_on_fractional_interest()
# exit()


# def test_make_node_staking_score():

