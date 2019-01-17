import logging
import os
import random
import time
import sys
from pprint import pprint


from hvm import constants

from hvm import MainnetChain
from hvm.chains.mainnet import (
    MAINNET_GENESIS_PARAMS,
    MAINNET_GENESIS_STATE,
    GENESIS_PRIVATE_KEY,
    GENESIS_WALLET_ADDRESS,
    TPC_CAP_TEST_GENESIS_PRIVATE_KEY,
    MAINNET_NETWORK_ID,
)

from hvm.constants import (
    BLANK_ROOT_HASH,
    ZERO_HASH32,
    EMPTY_SHA3,
    SLASH_WALLET_ADDRESS,
    NUMBER_OF_HEAD_HASH_TO_SAVE,
    TIME_BETWEEN_HEAD_HASH_SAVE,
    COIN_MATURE_TIME_FOR_STAKING,

    COLLATION_SIZE)


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

from helios_logging import (
    setup_helios_logging,
    with_queued_logging,
)

from eth_utils import (
    encode_hex,
    decode_hex,        
)
from helios.dev_tools import create_dev_test_random_blockchain_database, create_dev_test_blockchain_database_with_given_transactions
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
from eth_keys import keys

from eth_keys.datatypes import(
        BaseKey,
        PublicKey,
        PrivateKey
)

import matplotlib.pyplot as plt

from hvm.utils.profile import profile

#for testing purposes we will just have the primary private key hardcoded
#TODO: save to encrypted json file
#primary_private_keys = [b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5', b'\xa41\x95@\xbb\xa5\xde\xbbc\xffR\x8a\x18\x06\x95\xa3\xd7\xd2\x95]5{\x12\xe4n\xb6R\xd7S\x96\xf0+', b'\xd8>Fh\xefT\x04jf\x13\xca|E\xc4\x91\xed\x07\xcd\x02fW\xd8s;\xd8\xe4\xde\xb9\xbc\xe4\xf0I', b'\x83\x1d\xf6\xaf-\x00\xbfS4\x0f\xcds\x18"\xdd\x906]e\xfc\xe6\x0c?\xb1v20\xced7y\xf4', b")M\xf4\x1c\xb7\xe0Z\xf4\x17F\x9b\x089'\x004\xd3\x89\xd8\x80\xf5`\xa2\x11\x00\x90\xbd\x0f&KjZ", b'RI\xda\xbc7\xc4\xe8\tz\xfaI\x1f\xa1\x02{v\x0e\xac\x87W\xa2s\x81L4M\xad\xbd\xb3\x84\xaae', b'>kG\xd5\xb3qG\x84\xa6"\x1c~\xb6\xbf\x96\xac\n\x88\xfb\x05\x8aG\r\xe9Z\x16\x15\xb1P\xe0\xb7[', b'\x87\xf6\xb1\xa7v\x8bv<\xa3\xe5\xb18\xa7u\x99\xbaBa\xe9\xd5\x0e\xcb\x0f?\x84nZ\xba\xdf\xa3\x8a~', b'`$g\xe9\xa5r\xd2\xacG&\xf81^\x98\xf7\xda\xa5\xf4\x93)\xf3\x0c\x18\x84\xe4)!\x9dR\xa0\xac\xd3', b'\xcfd\xd5|\xe2\xf1\xda\xb9\x1f|\xb9\xdc\xeb \xd7\xb0\x81g\xdc\x03\xd6dQ\xf14\x19`\x94o\xf7\xc7\x1b', b'}LO\x14($d\n!\x1a\x91\xa8S\xb3\x05\xaa\x89\xf2\x0b\x97\xd3\x1c#\xe7\x86g`\xf1\x1a\xedXW']
from hvm.constants import random_private_keys
from hvm.vm.forks.helios_testnet.blocks import MicroBlock, HeliosTestnetBlock

def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(random_private_keys[instance_number])

SENDER = GENESIS_PRIVATE_KEY
RECEIVER = get_primary_node_private_helios_key(1)
RECEIVER2 = get_primary_node_private_helios_key(2)
RECEIVER3 = get_primary_node_private_helios_key(3)
RECEIVER4 = get_primary_node_private_helios_key(4)

log_level = getattr(logging, 'INFO')
logger, log_queue, listener = setup_helios_logging(log_level)
logger.propagate = False


def test_block_rewards_system():
    #The genesis chain will be adding a reward block. We need to generate fake NodeStakingScores from a bunch of other
    #nodes
    from helios.dev_tools import create_dev_fixed_blockchain_database
    import random

    # testdb = LevelDB('/home/tommy/.local/share/helios/instance_test/mainnet/chain/full/')
    # testdb = JournalDB(testdb)
    testdb = MemoryDB()

    private_keys = []
    for i in range(10):
        private_keys.append(get_primary_node_private_helios_key(i))

    now = int(time.time())
    coin_mature_time = constants.COIN_MATURE_TIME_FOR_STAKING
    key_balance_dict = {
        private_keys[0]: (1000, now - coin_mature_time * 10 - 100),
        private_keys[1]: (20000, now - coin_mature_time * 10 - 99),
        private_keys[2]: (34000, now - coin_mature_time * 10 - 98),
        private_keys[3]: (100000, now - coin_mature_time * 10 - 97),
        private_keys[4]: (140000, now - coin_mature_time * 10 - 96),
        private_keys[5]: (240000, now - coin_mature_time * 10 - 50),
        private_keys[6]: (300000, now - coin_mature_time * 10 - 45),
        private_keys[7]: (400000, now - coin_mature_time * 10 - 40),
        private_keys[8]: (100000, now-1),
        private_keys[9]: (1000000, now),# immature


    }
    create_dev_fixed_blockchain_database(testdb, key_balance_dict)


    from hvm.rlp.consensus import NodeStakingScore, stake_reward_bundle_or_binary

    chain = MainnetChain(testdb, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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
        node_staking_score = NodeStakingScore(recipient_node_wallet_address = GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                                              score = int(score),
                                              since_block_number = 0,
                                              timestamp = int(time.time()),
                                              head_hash_of_sender_chain = chain.chaindb.get_canonical_head_hash(private_key.public_key.to_canonical_address()),
                                              v = 0,
                                              r = 0,
                                              s = 0,
                                              )
        signed_node_staking_score = node_staking_score.get_signed(private_key,MAINNET_NETWORK_ID)
        node_staking_scores.append(signed_node_staking_score)
        score = score/5

    chain = MainnetChain(testdb, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    node_staking_scores.sort(key=lambda x: -1* x.score)
    for node_staking_score in node_staking_scores:
        node_staking_score.validate()
        print(node_staking_score.is_signature_valid)
        print(node_staking_score.sender)
        print(node_staking_score.score, chain.get_mature_stake(node_staking_score.sender, node_staking_score.timestamp))


    reward_bundle = chain.consensus_db.create_reward_bundle_for_block(GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), node_staking_scores, at_timestamp = int(time.time()))

    chain.consensus_db.validate_reward_bundle(reward_bundle, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), time.time())


    print(reward_bundle.reward_type_1.amount)
    print(reward_bundle.reward_type_2.amount)
    print(reward_bundle.reward_type_2.proof)

    initial_balance = chain.get_vm().state.account_db.get_balance(GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    print("balance before reward = ", initial_balance)

    chain.import_current_queue_block_with_reward(reward_bundle.reward_type_2.proof)

    final_balance = chain.get_vm().state.account_db.get_balance(GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    print("balance after reward = ",final_balance)
    assert((reward_bundle.reward_type_1.amount + reward_bundle.reward_type_2.amount) == (final_balance- initial_balance))





#
# test_block_rewards_system()
# sys.exit()