import logging
import os
import time
import sys
from pprint import pprint

import pytest

from hvm import constants

from hvm import TestnetChain
from hvm.chains.testnet import (
    TESTNET_GENESIS_PARAMS,
    TESTNET_GENESIS_STATE,
    TESTNET_GENESIS_PRIVATE_KEY,
    TESTNET_NETWORK_ID,
)

from eth_utils import to_wei

from hvm.types import Timestamp
from hvm.constants import (
    BLANK_ROOT_HASH,
    ZERO_HASH32,
    TIME_BETWEEN_HEAD_HASH_SAVE,
    GAS_TX,)

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
import random

from eth_utils import (
    encode_hex,
    decode_hex,
    keccak
)
from helios.dev_tools import (
    create_dev_test_random_blockchain_database,
    add_transactions_to_blockchain_db,
    create_dev_test_random_blockchain_db_with_reward_blocks,
    create_dev_test_blockchain_database_with_given_transactions,
    create_new_genesis_params_and_state,
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

from helios.rpc.format import block_to_dict

from hvm.exceptions import ValidationError

from hvm.utils.profile import profile

#for testing purposes we will just have the primary private key hardcoded
#TODO: save to encrypted json file
#primary_private_keys = [b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5', b'\xa41\x95@\xbb\xa5\xde\xbbc\xffR\x8a\x18\x06\x95\xa3\xd7\xd2\x95]5{\x12\xe4n\xb6R\xd7S\x96\xf0+', b'\xd8>Fh\xefT\x04jf\x13\xca|E\xc4\x91\xed\x07\xcd\x02fW\xd8s;\xd8\xe4\xde\xb9\xbc\xe4\xf0I', b'\x83\x1d\xf6\xaf-\x00\xbfS4\x0f\xcds\x18"\xdd\x906]e\xfc\xe6\x0c?\xb1v20\xced7y\xf4', b")M\xf4\x1c\xb7\xe0Z\xf4\x17F\x9b\x089'\x004\xd3\x89\xd8\x80\xf5`\xa2\x11\x00\x90\xbd\x0f&KjZ", b'RI\xda\xbc7\xc4\xe8\tz\xfaI\x1f\xa1\x02{v\x0e\xac\x87W\xa2s\x81L4M\xad\xbd\xb3\x84\xaae', b'>kG\xd5\xb3qG\x84\xa6"\x1c~\xb6\xbf\x96\xac\n\x88\xfb\x05\x8aG\r\xe9Z\x16\x15\xb1P\xe0\xb7[', b'\x87\xf6\xb1\xa7v\x8bv<\xa3\xe5\xb18\xa7u\x99\xbaBa\xe9\xd5\x0e\xcb\x0f?\x84nZ\xba\xdf\xa3\x8a~', b'`$g\xe9\xa5r\xd2\xacG&\xf81^\x98\xf7\xda\xa5\xf4\x93)\xf3\x0c\x18\x84\xe4)!\x9dR\xa0\xac\xd3', b'\xcfd\xd5|\xe2\xf1\xda\xb9\x1f|\xb9\xdc\xeb \xd7\xb0\x81g\xdc\x03\xd6dQ\xf14\x19`\x94o\xf7\xc7\x1b', b'}LO\x14($d\n!\x1a\x91\xa8S\xb3\x05\xaa\x89\xf2\x0b\x97\xd3\x1c#\xe7\x86g`\xf1\x1a\xedXW']
from hvm.constants import random_private_keys
from hvm.vm.forks.helios_testnet.blocks import HeliosMicroBlock, HeliosTestnetBlock

from tests.integration_test_helpers import (
    ensure_blockchain_databases_identical,
    ensure_chronological_block_hashes_are_identical
)

from hvm.exceptions import ParentNotFound

def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(random_private_keys[instance_number])
import time

SENDER = TESTNET_GENESIS_PRIVATE_KEY
RECEIVER = get_primary_node_private_helios_key(1)
RECEIVER2 = get_primary_node_private_helios_key(2)
RECEIVER3 = get_primary_node_private_helios_key(3)
RECEIVER4 = get_primary_node_private_helios_key(4)
RECEIVER5 = get_primary_node_private_helios_key(5)

test_hashes = [keccak(text = str(x)) for x in range(10)]
start = int(int(time.time()/TIME_BETWEEN_HEAD_HASH_SAVE)*TIME_BETWEEN_HEAD_HASH_SAVE)
end = int(start - TIME_BETWEEN_HEAD_HASH_SAVE*10)
test_timestamps = [x for x in range(start, end, -TIME_BETWEEN_HEAD_HASH_SAVE)]


def test_initialize_historical_root_hashes():
    testdb1 = MemoryDB()
    chain = TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    chain.chain_head_db.initialize_historical_root_hashes(test_hashes[0],test_timestamps[0])
    historical_root_hashes = chain.chain_head_db.get_historical_root_hashes()

    assert(historical_root_hashes == [[test_timestamps[0],test_hashes[0]]])

    chain.chain_head_db.initialize_historical_root_hashes(test_hashes[1], test_timestamps[0])
    historical_root_hashes = chain.chain_head_db.get_historical_root_hashes()

    assert (historical_root_hashes == [[test_timestamps[0], test_hashes[1]]])

#test_initialize_historical_root_hashes()


def test_save_single_historical_root_hash():
    testdb1 = MemoryDB()
    chain = TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    chain.chain_head_db.initialize_historical_root_hashes(test_hashes[0],test_timestamps[0])

    # make sure it doesn't duplicate if saved the same timestamp
    chain.chain_head_db.save_single_historical_root_hash(test_hashes[1], test_timestamps[0])

    historical_root_hashes = chain.chain_head_db.get_historical_root_hashes()

    assert (historical_root_hashes == [[test_timestamps[0], test_hashes[1]]])

    # Make sure it saves when different timestamp.
    chain.chain_head_db.save_single_historical_root_hash(test_hashes[1], test_timestamps[1])

    historical_root_hashes = chain.chain_head_db.get_historical_root_hashes()

    assert (historical_root_hashes == [[test_timestamps[1], test_hashes[1]],[test_timestamps[0], test_hashes[1]]])



#test_save_single_historical_root_hash()


