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
from helios.dev_tools import (
    create_dev_test_random_blockchain_database,
    create_dev_test_blockchain_database_with_given_transactions,
    create_blockchain_database_for_exceeding_tpc_cap
)
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

#
# #tx_list = [from priv_key, to priv_key, amount, timestamp]
# def create_dev_test_blockchain_database_with_given_transactions(base_db, tx_list: list):
#


# create_blockchain_database_for_exceeding_tpc_cap(10)
# sys.exit()

def test_min_allowed_gas_system():
    testdb1 = MemoryDB()

    tpc_of_blockchain_database = 1
    num_tpc_windows_to_go_back = 60
    create_blockchain_database_for_exceeding_tpc_cap(testdb1,tpc_of_blockchain_database, num_tpc_windows_to_go_back)

    # testdb1 = JournalDB(testdb1)

    node_1 = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    # Follow the process that consensus will be using to sync the min gas system

    local_tpc_cap = node_1.get_local_tpc_cap()

    init_min_gas_price = 1
    init_tpc_cap = local_tpc_cap
    init_tpc = 10
    #initialize the min gas system
    node_1.chaindb.initialize_historical_minimum_gas_price_at_genesis(init_min_gas_price, init_tpc_cap, init_tpc)

    historical_min_gas_price = node_1.chaindb.load_historical_minimum_gas_price()
    historical_network_tpc_capability = node_1.chaindb.load_historical_network_tpc_capability()
    historical_tpc = node_1.chaindb.load_historical_tx_per_centisecond()

    assert(all([x[1] == init_min_gas_price for x in historical_min_gas_price]))
    assert(all([x[1] == init_tpc_cap for x in historical_network_tpc_capability]))
    assert(all([x[1] == init_tpc for x in historical_tpc]))

    # update the newest tpc cap and check that it saved
    node_1.update_current_network_tpc_capability(local_tpc_cap, update_min_gas_price = True)
    historical_min_gas_price = node_1.chaindb.load_historical_minimum_gas_price()
    historical_tpc_cap = node_1.chaindb.load_historical_network_tpc_capability()
    historical_tpc = node_1.chaindb.load_historical_tx_per_centisecond()
    assert(historical_tpc_cap[-1][1] == local_tpc_cap)
    assert(historical_min_gas_price[-1][1] == 1)

    # Updating tpc will cause it to see that the initial tpc doesnt match the blockchain database, and correct it.
    # It will only go back at most 60 centiseconds, or at least 50.

    # need to say == True to make pytest happy
    assert(all([x[1] == tpc_of_blockchain_database for x in historical_tpc[-50:-1]]))

    # the given tpc from the database is below the threshold. So min gas should stay at 1
    assert(all([x[1] == 1 for x in historical_min_gas_price[-50:]]))

    #
    #
    #

    #now lets create a database where the tx/sec is above the threshold and make sure hostorical has price increases

    testdb1 = MemoryDB()

    tpc_of_blockchain_database = 4
    num_tpc_windows_to_go_back = 60
    create_blockchain_database_for_exceeding_tpc_cap(testdb1, tpc_of_blockchain_database, num_tpc_windows_to_go_back)

    # testdb1 = JournalDB(testdb1)

    node_1 = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    # Follow the process that consensus will be using to sync the min gas system


    init_min_gas_price = 1
    init_tpc_cap = 2
    init_tpc = 1
    # initialize the min gas system
    node_1.chaindb.initialize_historical_minimum_gas_price_at_genesis(init_min_gas_price, init_tpc_cap, init_tpc)

    historical_min_gas_price = node_1.chaindb.load_historical_minimum_gas_price()
    historical_network_tpc_capability = node_1.chaindb.load_historical_network_tpc_capability()
    historical_tpc = node_1.chaindb.load_historical_tx_per_centisecond()

    assert (all([x[1] == init_min_gas_price for x in historical_min_gas_price]))
    assert (all([x[1] == init_tpc_cap for x in historical_network_tpc_capability]))
    assert (all([x[1] == init_tpc for x in historical_tpc]))

    # update the newest tpc cap and check that it saved
    node_1.update_current_network_tpc_capability(init_tpc_cap, update_min_gas_price=True)
    historical_min_gas_price = node_1.chaindb.load_historical_minimum_gas_price()
    historical_tpc_cap = node_1.chaindb.load_historical_network_tpc_capability()
    historical_tpc = node_1.chaindb.load_historical_tx_per_centisecond()


    # plt.plot([x[1] for x in historical_min_gas_price])
    # plt.show()

    assert (historical_tpc_cap[-1][1] == init_tpc_cap)
    assert (historical_min_gas_price[-1][1] > 1)

    # Updating tpc will cause it to see that the initial tpc doesnt match the blockchain database, and correct it.
    # It will only go back at most 60 centiseconds, or at least 50.

    #need to say == True to make pytest happy
    assert (all([x[1] == tpc_of_blockchain_database for x in historical_tpc[-50:-1]]))


# test_min_allowed_gas_system()
# exit()