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


from hvm.types import Timestamp

import pytest

from hvm.exceptions import ValidationError, NotEnoughProofsOrStakeForRewardType2Proof, RewardAmountRoundsToZero, ReplacingBlocksNotAllowed

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
    to_wei,
)
from helios.dev_tools import create_dev_test_random_blockchain_database, \
    create_dev_test_blockchain_database_with_given_transactions, add_transactions_to_blockchain_db, \
    create_valid_block_at_timestamp
from eth_keys import keys
from sys import exit

from trie import (
    HexaryTrie,
)
from hvm.db.hash_trie import HashTrie

from hvm.db.chain_head import ChainHeadDB

from eth_utils import (
    int_to_big_endian,
    big_endian_to_int,
)
from helios.dev_tools import create_dev_fixed_blockchain_database
from eth_keys import keys

from eth_keys.datatypes import(
        BaseKey,
        PublicKey,
        PrivateKey
)
from hvm.rlp.consensus import NodeStakingScore, stake_reward_bundle_or_binary

# import matplotlib.pyplot as plt

from hvm.utils.profile import profile

#for testing purposes we will just have the primary private key hardcoded
#TODO: save to encrypted json file
#primary_private_keys = [b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5', b'\xa41\x95@\xbb\xa5\xde\xbbc\xffR\x8a\x18\x06\x95\xa3\xd7\xd2\x95]5{\x12\xe4n\xb6R\xd7S\x96\xf0+', b'\xd8>Fh\xefT\x04jf\x13\xca|E\xc4\x91\xed\x07\xcd\x02fW\xd8s;\xd8\xe4\xde\xb9\xbc\xe4\xf0I', b'\x83\x1d\xf6\xaf-\x00\xbfS4\x0f\xcds\x18"\xdd\x906]e\xfc\xe6\x0c?\xb1v20\xced7y\xf4', b")M\xf4\x1c\xb7\xe0Z\xf4\x17F\x9b\x089'\x004\xd3\x89\xd8\x80\xf5`\xa2\x11\x00\x90\xbd\x0f&KjZ", b'RI\xda\xbc7\xc4\xe8\tz\xfaI\x1f\xa1\x02{v\x0e\xac\x87W\xa2s\x81L4M\xad\xbd\xb3\x84\xaae', b'>kG\xd5\xb3qG\x84\xa6"\x1c~\xb6\xbf\x96\xac\n\x88\xfb\x05\x8aG\r\xe9Z\x16\x15\xb1P\xe0\xb7[', b'\x87\xf6\xb1\xa7v\x8bv<\xa3\xe5\xb18\xa7u\x99\xbaBa\xe9\xd5\x0e\xcb\x0f?\x84nZ\xba\xdf\xa3\x8a~', b'`$g\xe9\xa5r\xd2\xacG&\xf81^\x98\xf7\xda\xa5\xf4\x93)\xf3\x0c\x18\x84\xe4)!\x9dR\xa0\xac\xd3', b'\xcfd\xd5|\xe2\xf1\xda\xb9\x1f|\xb9\xdc\xeb \xd7\xb0\x81g\xdc\x03\xd6dQ\xf14\x19`\x94o\xf7\xc7\x1b', b'}LO\x14($d\n!\x1a\x91\xa8S\xb3\x05\xaa\x89\xf2\x0b\x97\xd3\x1c#\xe7\x86g`\xf1\x1a\xedXW']
from hvm.constants import random_private_keys, GAS_TX
from hvm.vm.forks.helios_testnet.blocks import HeliosMicroBlock, HeliosTestnetBlock

def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(random_private_keys[instance_number])

private_keys = []
for i in range(10):
    private_keys.append(get_primary_node_private_helios_key(i))

SENDER = TESTNET_GENESIS_PRIVATE_KEY
RECEIVER = get_primary_node_private_helios_key(1)
RECEIVER2 = get_primary_node_private_helios_key(2)
RECEIVER3 = get_primary_node_private_helios_key(3)
RECEIVER4 = get_primary_node_private_helios_key(4)

def create_reward_test_blockchain_database():
    testdb = MemoryDB()

    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    coin_mature_time = chain.get_vm(timestamp=Timestamp(int(time.time()))).consensus_db.coin_mature_time_for_staking
    min_time_between_blocks = chain.get_vm(timestamp=Timestamp(int(time.time()))).min_time_between_blocks
    required_stake_for_reward_type_2_proof = chain.get_consensus_db(timestamp=Timestamp(int(time.time()))).required_stake_for_reward_type_2_proof


    now = int(time.time())
    start = now - max((coin_mature_time * 2), (min_time_between_blocks * 20))
    key_balance_dict = {}
    for i in range(10):
        key_balance_dict[private_keys[i]] = (
        required_stake_for_reward_type_2_proof, start + min_time_between_blocks * i)

    create_dev_fixed_blockchain_database(testdb, key_balance_dict)
    return testdb

# This test can only work if min time between reward blocks is set to a small number
def _test_block_rewards_system():
    #The genesis chain will be adding a reward block. We need to generate fake NodeStakingScores from a bunch of other
    #nodes

    # testdb = LevelDB('/home/tommy/.local/share/helios/instance_test/mainnet/chain/full/')
    # testdb = JournalDB(testdb)
    testdb = create_reward_test_blockchain_database()

    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    coin_mature_time = chain.get_vm(timestamp=Timestamp(int(time.time()))).consensus_db.coin_mature_time_for_staking
    min_time_between_blocks = chain.get_vm(timestamp=Timestamp(int(time.time()))).min_time_between_blocks
    # now = int(time.time())
    # start = now - max((coin_mature_time * 2), (min_time_between_blocks*20))
    # key_balance_dict = {
    #     private_keys[0]: (to_wei(10, 'ether'), start),
    #     private_keys[1]: (to_wei(200, 'ether'), start + min_time_between_blocks * 1),
    #     private_keys[2]: (to_wei(340, 'ether'), start + min_time_between_blocks * 2),
    #     private_keys[3]: (to_wei(1000, 'ether'), start + min_time_between_blocks * 3),
    #     private_keys[4]: (to_wei(1400, 'ether'), start + min_time_between_blocks * 4),
    #     private_keys[5]: (to_wei(2400, 'ether'), start + min_time_between_blocks * 5),
    #     private_keys[6]: (to_wei(3000, 'ether'), start + min_time_between_blocks * 6),
    #     private_keys[7]: (to_wei(4000, 'ether'), start + min_time_between_blocks * 7),
    #     private_keys[8]: (to_wei(1000, 'ether'), start + min_time_between_blocks * 8),
    #     private_keys[9]: (to_wei(10000, 'ether'), now-coin_mature_time+1),# immature
    # }
    # create_dev_fixed_blockchain_database(testdb, key_balance_dict)

    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    # class NodeStakingScore(rlp.Serializable, metaclass=ABCMeta):
    #     fields = [
    #         ('recipient_node_wallet_address', address),
    #         ('score', f_big_endian_int),
    #         ('since_block_number', f_big_endian_int),
    #         ('timestamp', f_big_endian_int),
    #         ('v', big_endian_int),
    #         ('r', big_endian_int),
    #         ('s', big_endian_int),
    #     ]

    node_staking_scores = []

    score = 1000000
    for private_key in private_keys:
        node_staking_score = NodeStakingScore(recipient_node_wallet_address = TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                                              score = int(score),
                                              since_block_number = 0,
                                              timestamp = int(time.time()),
                                              head_hash_of_sender_chain = chain.chaindb.get_canonical_head_hash(private_key.public_key.to_canonical_address()),
                                              v = 0,
                                              r = 0,
                                              s = 0,
                                              )
        signed_node_staking_score = node_staking_score.get_signed(private_key,TESTNET_NETWORK_ID)
        node_staking_scores.append(signed_node_staking_score)
        score = score/5

    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    node_staking_scores.sort(key=lambda x: -1* x.score)
    for node_staking_score in node_staking_scores:
        node_staking_score.validate()
        print(node_staking_score.is_signature_valid)
        print(node_staking_score.sender)
        print(node_staking_score.score, chain.get_mature_stake(node_staking_score.sender, node_staking_score.timestamp))


    reward_bundle = chain.get_consensus_db().create_reward_bundle_for_block(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), node_staking_scores, at_timestamp = int(time.time()))


    chain.get_consensus_db().validate_reward_bundle(reward_bundle, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), int(time.time()))

    print('AAAAAAAAAAA')
    print(reward_bundle.reward_type_1.amount)
    print(reward_bundle.reward_type_2.amount)
    print(reward_bundle.reward_type_2.proof[0].score)


    initial_balance = chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    print("balance before reward = ", initial_balance)

    chain.import_current_queue_block_with_reward(reward_bundle.reward_type_2.proof)

    final_balance = chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    print("balance after reward = ",final_balance)
    assert((reward_bundle.reward_type_1.amount + reward_bundle.reward_type_2.amount) == (final_balance- initial_balance))

    print("waiting {} seconds before importing the next block".format(min_time_between_blocks))
    time.sleep(min_time_between_blocks)

    proof_chain = TestnetChain(testdb, private_keys[1].public_key.to_canonical_address(), private_keys[1])
    mature_stake = proof_chain.get_mature_stake()
    print("proof chain mature stake")
    print(mature_stake)

    staking_score = proof_chain.get_signed_peer_score_string_private_key(private_keys[1].to_bytes(), private_keys[0].public_key.to_canonical_address())
    staking_score = staking_score.copy(score=1532)
    staking_score = staking_score.get_signed(private_keys[1], proof_chain.network_id)
    print('staking score')
    print(staking_score.score)

    # fields = [
    #     ('recipient_node_wallet_address', address),
    #     ('score', f_big_endian_int),  # a score out of 1,000,000
    #     ('since_block_number', f_big_endian_int),
    #     ('timestamp', f_big_endian_int),
    #     ('head_hash_of_sender_chain', hash32),
    #     ('v', big_endian_int),
    #     ('r', big_endian_int),
    #     ('s', big_endian_int),
    # ]
    #
    reward_chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])
    reward_bundle = reward_chain.get_consensus_db().create_reward_bundle_for_block(private_keys[0].public_key.to_canonical_address(), [staking_score],at_timestamp=Timestamp(int(time.time())))
    print("reward type 2 amount")
    print(reward_bundle.reward_type_2.amount)
    print("reward type 2 proof")
    print(reward_bundle.reward_type_2.proof)
    reward_chain.import_current_queue_block_with_reward([staking_score])

    # todo: this will fail if the reward block time is too long. Need to manually set it to a small number for the test... or manually make the blocks older?
    print("waiting {} seconds before importing the next block".format(min_time_between_blocks))
    time.sleep(min_time_between_blocks)

    proof_chain = TestnetChain(testdb, private_keys[1].public_key.to_canonical_address(), private_keys[1])
    mature_stake = proof_chain.get_mature_stake()
    print("proof chain mature stake")
    print(mature_stake)

    staking_score = proof_chain.get_signed_peer_score_string_private_key(private_keys[1].to_bytes(), private_keys[
        0].public_key.to_canonical_address())
    staking_score = staking_score.copy(score=1000000)
    staking_score = staking_score.get_signed(private_keys[1], proof_chain.network_id)
    print('staking score')
    print(staking_score.score)

    # fields = [
    #     ('recipient_node_wallet_address', address),
    #     ('score', f_big_endian_int),  # a score out of 1,000,000
    #     ('since_block_number', f_big_endian_int),
    #     ('timestamp', f_big_endian_int),
    #     ('head_hash_of_sender_chain', hash32),
    #     ('v', big_endian_int),
    #     ('r', big_endian_int),
    #     ('s', big_endian_int),
    # ]
    #
    reward_chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])
    reward_bundle = reward_chain.get_consensus_db().create_reward_bundle_for_block(
        private_keys[0].public_key.to_canonical_address(), [staking_score], at_timestamp=Timestamp(int(time.time())))
    print("reward type 2 amount")
    print(reward_bundle.reward_type_2.amount)
    print("reward type 2 proof")
    print(reward_bundle.reward_type_2.proof)
    reward_chain.import_current_queue_block_with_reward([staking_score])

#
# test_block_rewards_system()
# sys.exit()




def test_invalid_proofs_signed_by_importing_chain():

    testdb = create_reward_test_blockchain_database()

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    required_number_of_proofs_for_reward_type_2_proof = chain.get_consensus_db(timestamp=Timestamp(int(time.time()))).required_number_of_proofs_for_reward_type_2_proof

    node_staking_scores = []

    # First score/proof is from instance 0
    current_private_key = private_keys[0]
    node_staking_score = NodeStakingScore(
        recipient_node_wallet_address=current_private_key.public_key.to_canonical_address(),
        score=int(1000000),
        since_block_number=0,
        timestamp=int(time.time()),
        head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
            current_private_key.public_key.to_canonical_address()),
        v=0,
        r=0,
        s=0,
        )
    signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
    node_staking_scores.append(signed_node_staking_score)

    score = 1000000
    for i in range(1, required_number_of_proofs_for_reward_type_2_proof):
        # Second score/proof is from instance 1
        current_private_key = private_keys[i]
        node_staking_score = NodeStakingScore(
            recipient_node_wallet_address=private_keys[0].public_key.to_canonical_address(),
            score=int(score),
            since_block_number=0,
            timestamp=int(time.time()),
            head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
                current_private_key.public_key.to_canonical_address()),
            v=0,
            r=0,
            s=0,
            )
        signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
        node_staking_scores.append(signed_node_staking_score)


    # Now we try to import the reward block with instance 0
    reward_chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    with pytest.raises(ValidationError):
        reward_chain.import_current_queue_block_with_reward(node_staking_scores)

# test_invalid_proofs_signed_by_importing_chain()
# exit()

def test_invalid_proofs_all_from_same_wallet():

    testdb = create_reward_test_blockchain_database()

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    required_number_of_proofs_for_reward_type_2_proof = chain.get_consensus_db(timestamp=Timestamp(int(time.time()))).required_number_of_proofs_for_reward_type_2_proof

    node_staking_scores = []

    score = 1000000
    for i in range(1, 10):
        # Second score/proof is from instance 1
        current_private_key = private_keys[1]
        node_staking_score = NodeStakingScore(
            recipient_node_wallet_address=private_keys[0].public_key.to_canonical_address(),
            score=int(score-i),
            since_block_number=0,
            timestamp=int(time.time()),
            head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
                current_private_key.public_key.to_canonical_address()),
            v=0,
            r=0,
            s=0,
            )
        signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
        node_staking_scores.append(signed_node_staking_score)

    # Now we try to import the reward block with instance 0
    reward_chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    with pytest.raises(ValidationError):
        reward_chain.import_current_queue_block_with_reward(node_staking_scores)

# test_invalid_proofs_all_from_same_wallet()
# exit()


def test_invalid_proofs_score_too_large():

    testdb = create_reward_test_blockchain_database()

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    required_number_of_proofs_for_reward_type_2_proof = chain.get_consensus_db(timestamp=Timestamp(int(time.time()))).required_number_of_proofs_for_reward_type_2_proof

    node_staking_scores = []

    # First score/proof has a score too large
    current_private_key = private_keys[1]
    node_staking_score = NodeStakingScore(
        recipient_node_wallet_address=private_keys[0].public_key.to_canonical_address(),
        score=int(1000001),
        since_block_number=0,
        timestamp=int(time.time()),
        head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
            current_private_key.public_key.to_canonical_address()),
        v=0,
        r=0,
        s=0,
    )
    signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
    node_staking_scores.append(signed_node_staking_score)

    score = 1000000
    for i in range(2, 10):
        # Second score/proof is from instance 1
        current_private_key = private_keys[i]
        node_staking_score = NodeStakingScore(
            recipient_node_wallet_address=private_keys[0].public_key.to_canonical_address(),
            score=int(score-i),
            since_block_number=0,
            timestamp=int(time.time()),
            head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
                current_private_key.public_key.to_canonical_address()),
            v=0,
            r=0,
            s=0,
            )
        signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
        node_staking_scores.append(signed_node_staking_score)

    # Now we try to import the reward block with instance 0
    reward_chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    with pytest.raises(ValidationError):
        reward_chain.import_current_queue_block_with_reward(node_staking_scores)

# test_invalid_proofs_score_too_large()
# exit()


def test_invalid_proofs_score_wrong_chain_head():

    testdb = create_reward_test_blockchain_database()

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])
    min_time_between_blocks = chain.get_vm(timestamp=Timestamp(int(time.time()))).min_time_between_blocks
    tx_list = [[private_keys[1], private_keys[0], to_wei(1, 'ether'), int(int(time.time())-min_time_between_blocks*10)]]

    add_transactions_to_blockchain_db(testdb, tx_list)

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    required_number_of_proofs_for_reward_type_2_proof = chain.get_consensus_db(timestamp=Timestamp(int(time.time()))).required_number_of_proofs_for_reward_type_2_proof

    node_staking_scores = []

    # First score/proof with the incorrect head hash. It is using the head hash of an earlier block, not the header.
    current_private_key = private_keys[1]
    node_staking_score = NodeStakingScore(
        recipient_node_wallet_address=private_keys[0].public_key.to_canonical_address(),
        score=int(1000000),
        since_block_number=0,
        timestamp=int(time.time()),
        head_hash_of_sender_chain=chain.chaindb.get_canonical_block_hash(0,
            current_private_key.public_key.to_canonical_address()),
        v=0,
        r=0,
        s=0,
    )
    signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
    node_staking_scores.append(signed_node_staking_score)

    score = 100000
    for i in range(2, 10):
        # Second score/proof is from instance 1
        current_private_key = private_keys[i]
        node_staking_score = NodeStakingScore(
            recipient_node_wallet_address=private_keys[0].public_key.to_canonical_address(),
            score=int(score-i),
            since_block_number=0,
            timestamp=int(time.time()),
            head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
                current_private_key.public_key.to_canonical_address()),
            v=0,
            r=0,
            s=0,
            )
        signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
        node_staking_scores.append(signed_node_staking_score)

    # Now we try to import the reward block with instance 0
    reward_chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    with pytest.raises(ValidationError):
        reward_chain.import_current_queue_block_with_reward(node_staking_scores)

# test_invalid_proofs_score_wrong_chain_head()
# exit()



def test_invalid_proofs_created_for_different_chain():

    testdb = create_reward_test_blockchain_database()

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])
    min_time_between_blocks = chain.get_vm(timestamp=Timestamp(int(time.time()))).min_time_between_blocks
    tx_list = [[private_keys[1], private_keys[0], to_wei(1, 'ether'), int(int(time.time())-min_time_between_blocks*10)]]

    add_transactions_to_blockchain_db(testdb, tx_list)

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    required_number_of_proofs_for_reward_type_2_proof = chain.get_consensus_db(timestamp=Timestamp(int(time.time()))).required_number_of_proofs_for_reward_type_2_proof

    node_staking_scores = []

    # First score/proof with the incorrect head hash
    current_private_key = private_keys[1]
    node_staking_score = NodeStakingScore(
        recipient_node_wallet_address=private_keys[1].public_key.to_canonical_address(),
        score=int(1000000),
        since_block_number=0,
        timestamp=int(time.time()),
        head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
            current_private_key.public_key.to_canonical_address()),
        v=0,
        r=0,
        s=0,
    )
    signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
    node_staking_scores.append(signed_node_staking_score)

    score = 100000
    for i in range(2, 10):
        # Second score/proof is from instance 1
        current_private_key = private_keys[i]
        node_staking_score = NodeStakingScore(
            recipient_node_wallet_address=private_keys[0].public_key.to_canonical_address(),
            score=int(score-i),
            since_block_number=0,
            timestamp=int(time.time()),
            head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
                current_private_key.public_key.to_canonical_address()),
            v=0,
            r=0,
            s=0,
            )
        signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
        node_staking_scores.append(signed_node_staking_score)

    # Now we try to import the reward block with instance 0
    reward_chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    with pytest.raises(ValidationError):
        reward_chain.import_current_queue_block_with_reward(node_staking_scores)

# test_invalid_proofs_created_for_different_chain()
# exit()


def test_invalid_proofs_previous_reward_block_incorrect():

    testdb = create_reward_test_blockchain_database()

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])
    min_time_between_blocks = chain.get_vm(timestamp=Timestamp(int(time.time()))).min_time_between_blocks
    tx_list = [[private_keys[1], private_keys[0], to_wei(1, 'ether'), int(int(time.time())-min_time_between_blocks*10)]]

    add_transactions_to_blockchain_db(testdb, tx_list)

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    required_number_of_proofs_for_reward_type_2_proof = chain.get_consensus_db(timestamp=Timestamp(int(time.time()))).required_number_of_proofs_for_reward_type_2_proof

    node_staking_scores = []

    # First score/proof with the incorrect head hash
    current_private_key = private_keys[1]
    node_staking_score = NodeStakingScore(
        recipient_node_wallet_address=private_keys[0].public_key.to_canonical_address(),
        score=int(1000000),
        since_block_number=1,
        timestamp=int(time.time()),
        head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
            current_private_key.public_key.to_canonical_address()),
        v=0,
        r=0,
        s=0,
    )
    signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
    node_staking_scores.append(signed_node_staking_score)

    score = 100000
    for i in range(2, 10):
        # Second score/proof is from instance 1
        current_private_key = private_keys[i]
        node_staking_score = NodeStakingScore(
            recipient_node_wallet_address=private_keys[0].public_key.to_canonical_address(),
            score=int(score-i),
            since_block_number=1,
            timestamp=int(time.time()),
            head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
                current_private_key.public_key.to_canonical_address()),
            v=0,
            r=0,
            s=0,
            )
        signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
        node_staking_scores.append(signed_node_staking_score)

    # Now we try to import the reward block with instance 0
    reward_chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    with pytest.raises(ValidationError):
        reward_chain.import_current_queue_block_with_reward(node_staking_scores)

# test_invalid_proofs_previous_reward_block_incorrect()
# exit()

def test_invalid_proofs_timestamp_in_future():

    testdb = create_reward_test_blockchain_database()

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])
    min_time_between_blocks = chain.get_vm(timestamp=Timestamp(int(time.time()))).min_time_between_blocks
    tx_list = [[private_keys[1], private_keys[0], to_wei(1, 'ether'), int(int(time.time())-min_time_between_blocks*10)]]

    add_transactions_to_blockchain_db(testdb, tx_list)

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    required_number_of_proofs_for_reward_type_2_proof = chain.get_consensus_db(timestamp=Timestamp(int(time.time()))).required_number_of_proofs_for_reward_type_2_proof

    node_staking_scores = []

    # First score/proof with timestamp far in future
    current_private_key = private_keys[1]
    node_staking_score = NodeStakingScore(
        recipient_node_wallet_address=private_keys[0].public_key.to_canonical_address(),
        score=int(1000000),
        since_block_number=0,
        timestamp=int(time.time())+60*10,
        head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
            current_private_key.public_key.to_canonical_address()),
        v=0,
        r=0,
        s=0,
    )
    signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
    node_staking_scores.append(signed_node_staking_score)

    score = 100000
    for i in range(2, 10):
        # Second score/proof is from instance 1
        current_private_key = private_keys[i]
        node_staking_score = NodeStakingScore(
            recipient_node_wallet_address=private_keys[0].public_key.to_canonical_address(),
            score=int(score-i),
            since_block_number=1,
            timestamp=int(time.time()),
            head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
                current_private_key.public_key.to_canonical_address()),
            v=0,
            r=0,
            s=0,
            )
        signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
        node_staking_scores.append(signed_node_staking_score)

    # Now we try to import the reward block with instance 0
    reward_chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    with pytest.raises(ValidationError):
        reward_chain.import_current_queue_block_with_reward(node_staking_scores)

# test_invalid_proofs_timestamp_in_future()
# exit()


def test_invalid_proofs_timestamp_in_past():

    testdb = create_reward_test_blockchain_database()

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])
    min_time_between_blocks = chain.get_vm(timestamp=Timestamp(int(time.time()))).min_time_between_blocks
    tx_list = [[private_keys[1], private_keys[0], to_wei(1, 'ether'), int(int(time.time())-min_time_between_blocks*10)]]

    add_transactions_to_blockchain_db(testdb, tx_list)

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    required_number_of_proofs_for_reward_type_2_proof = chain.get_consensus_db(timestamp=Timestamp(int(time.time()))).required_number_of_proofs_for_reward_type_2_proof

    node_staking_scores = []

    # First score/proof with timestamp far in future
    current_private_key = private_keys[1]
    node_staking_score = NodeStakingScore(
        recipient_node_wallet_address=private_keys[0].public_key.to_canonical_address(),
        score=int(1000000),
        since_block_number=0,
        timestamp=int(time.time())-60*10,
        head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
            current_private_key.public_key.to_canonical_address()),
        v=0,
        r=0,
        s=0,
    )
    signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
    node_staking_scores.append(signed_node_staking_score)

    score = 100000
    for i in range(2, 10):
        # Second score/proof is from instance 1
        current_private_key = private_keys[i]
        node_staking_score = NodeStakingScore(
            recipient_node_wallet_address=private_keys[0].public_key.to_canonical_address(),
            score=int(score-i),
            since_block_number=1,
            timestamp=int(time.time()),
            head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
                current_private_key.public_key.to_canonical_address()),
            v=0,
            r=0,
            s=0,
            )
        signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
        node_staking_scores.append(signed_node_staking_score)

    # Now we try to import the reward block with instance 0
    reward_chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    with pytest.raises(ValidationError):
        reward_chain.import_current_queue_block_with_reward(node_staking_scores)

# test_invalid_proofs_timestamp_in_past()
# exit()

def test_invalid_proofs_not_enough_proofs():

    testdb = create_reward_test_blockchain_database()

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])
    min_time_between_blocks = chain.get_vm(timestamp=Timestamp(int(time.time()))).min_time_between_blocks
    tx_list = [[private_keys[1], private_keys[0], to_wei(1, 'ether'), int(int(time.time())-min_time_between_blocks*10)]]

    add_transactions_to_blockchain_db(testdb, tx_list)

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    required_number_of_proofs_for_reward_type_2_proof = chain.get_consensus_db(timestamp=Timestamp(int(time.time()))).required_number_of_proofs_for_reward_type_2_proof

    node_staking_scores = []

    # First score/proof with timestamp far in future
    current_private_key = private_keys[1]
    node_staking_score = NodeStakingScore(
        recipient_node_wallet_address=private_keys[0].public_key.to_canonical_address(),
        score=int(1000000),
        since_block_number=0,
        timestamp=int(time.time())-60*10,
        head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
            current_private_key.public_key.to_canonical_address()),
        v=0,
        r=0,
        s=0,
    )
    signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
    node_staking_scores.append(signed_node_staking_score)

    # Now we try to import the reward block with instance 0
    reward_chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    with pytest.raises(NotEnoughProofsOrStakeForRewardType2Proof):
        reward_chain.import_current_queue_block_with_reward(node_staking_scores)

# test_invalid_proofs_not_enough_proofs()
# exit()

def test_invalid_proofs_no_proofs():

    testdb = create_reward_test_blockchain_database()

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])
    min_time_between_blocks = chain.get_vm(timestamp=Timestamp(int(time.time()))).min_time_between_blocks
    tx_list = [[private_keys[1], private_keys[0], to_wei(1, 'ether'), int(int(time.time())-min_time_between_blocks*10)]]

    add_transactions_to_blockchain_db(testdb, tx_list)

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    required_number_of_proofs_for_reward_type_2_proof = chain.get_consensus_db(timestamp=Timestamp(int(time.time()))).required_number_of_proofs_for_reward_type_2_proof


    # Now we try to import the reward block with instance 0
    reward_chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    with pytest.raises(RewardAmountRoundsToZero):
        imported_block = reward_chain.import_current_queue_block_with_reward([])

# test_invalid_proofs_no_proofs()
# exit()


def test_invalid_proofs_not_enough_stake():
    testdb = MemoryDB()

    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    coin_mature_time = chain.get_vm(timestamp=Timestamp(int(time.time()))).consensus_db.coin_mature_time_for_staking
    min_time_between_blocks = chain.get_vm(timestamp=Timestamp(int(time.time()))).min_time_between_blocks
    now = int(time.time())
    start = now - max((coin_mature_time * 2), (min_time_between_blocks * 20))
    key_balance_dict = {
        private_keys[0]: (to_wei(1, 'ether'), start),
        private_keys[1]: (to_wei(1, 'ether'), start + min_time_between_blocks * 1),
        private_keys[2]: (to_wei(1, 'ether'), start + min_time_between_blocks * 2),
        private_keys[3]: (to_wei(1, 'ether'), start + min_time_between_blocks * 3),
        private_keys[4]: (to_wei(1, 'ether'), start + min_time_between_blocks * 4),
        private_keys[5]: (to_wei(1, 'ether'), start + min_time_between_blocks * 5),
        private_keys[6]: (to_wei(1, 'ether'), start + min_time_between_blocks * 6),
        private_keys[7]: (to_wei(1, 'ether'), start + min_time_between_blocks * 7),
        private_keys[8]: (to_wei(1, 'ether'), start + min_time_between_blocks * 8),
        private_keys[9]: (to_wei(1, 'ether'), now - coin_mature_time + 1),  # immature
    }
    create_dev_fixed_blockchain_database(testdb, key_balance_dict)

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    node_staking_scores = []

    # First score/proof with timestamp far in future
    current_private_key = private_keys[1]
    node_staking_score = NodeStakingScore(
        recipient_node_wallet_address=private_keys[0].public_key.to_canonical_address(),
        score=int(1000000),
        since_block_number=0,
        timestamp=int(time.time())-60*10,
        head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
            current_private_key.public_key.to_canonical_address()),
        v=0,
        r=0,
        s=0,
    )
    signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
    node_staking_scores.append(signed_node_staking_score)

    score = 100000
    for i in range(2, 10):
        # Second score/proof is from instance 1
        current_private_key = private_keys[i]
        node_staking_score = NodeStakingScore(
            recipient_node_wallet_address=private_keys[0].public_key.to_canonical_address(),
            score=int(score-i),
            since_block_number=1,
            timestamp=int(time.time()),
            head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
                current_private_key.public_key.to_canonical_address()),
            v=0,
            r=0,
            s=0,
            )
        signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
        node_staking_scores.append(signed_node_staking_score)

    # Now we try to import the reward block with instance 0
    reward_chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    with pytest.raises(NotEnoughProofsOrStakeForRewardType2Proof):
        reward_chain.import_current_queue_block_with_reward(node_staking_scores)

# test_invalid_proofs_not_enough_stake()
# exit()

#import block with reward with proof from another chain, then import a block on the other chain with a timestamp before the reward block, breaking chronological consistency
def test_break_chronological_consistency_1():
    testdb = create_reward_test_blockchain_database()

    chain = TestnetChain(testdb, private_keys[1].public_key.to_canonical_address(), private_keys[1])

    tx_nonce = chain.get_current_queue_block_nonce()
    tx = chain.create_and_sign_transaction(nonce = tx_nonce,
        gas_price=to_wei(1, 'gwei'),
        gas=GAS_TX,
        to=private_keys[0].public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )
    new_block_to_import = create_valid_block_at_timestamp(testdb,
                                    private_keys[1],
                                    transactions=[tx],
                                    receive_transactions=None,
                                    reward_bundle=None,
                                    timestamp=int(time.time()-1))

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])
    node_staking_scores = []

    score = 100000
    for i in range(1, 10):
        # Second score/proof is from instance 1
        current_private_key = private_keys[i]
        node_staking_score = NodeStakingScore(
            recipient_node_wallet_address=private_keys[0].public_key.to_canonical_address(),
            score=int(score-i),
            since_block_number=0,
            timestamp=int(time.time()),
            head_hash_of_sender_chain=chain.chaindb.get_canonical_head_hash(
                current_private_key.public_key.to_canonical_address()),
            v=0,
            r=0,
            s=0,
            )
        signed_node_staking_score = node_staking_score.get_signed(current_private_key, TESTNET_NETWORK_ID)
        node_staking_scores.append(signed_node_staking_score)

    # Now we try to import the reward block with instance 0
    reward_chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    reward_block = reward_chain.import_current_queue_block_with_reward(node_staking_scores)

    print("reward block timestamp {}".format(reward_block.header.timestamp))
    for proof in reward_block.reward_bundle.reward_type_2.proof:
        print(encode_hex(proof.sender))
        for i in range(1, 10):
            if proof.sender == private_keys[i].public_key.to_canonical_address():
                print("proof from {}".format(i))

    print("new_block_to_import timestamp {}".format(new_block_to_import.header.timestamp))
    print("new_block_to_import chain address {}".format(encode_hex(new_block_to_import.header.chain_address)))
    # Now we import a block on private key 1 with a timestamp set to 10 seconds ago
    chain = TestnetChain(testdb, private_keys[1].public_key.to_canonical_address(), private_keys[1])
    with pytest.raises(ReplacingBlocksNotAllowed):
        chain.import_block(new_block_to_import, allow_replacement=False)

# test_break_chronological_consistency_1()
# exit()