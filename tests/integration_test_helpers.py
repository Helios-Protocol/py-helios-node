import logging
import os
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
    BLANK_ROOT_HASH,
    ZERO_HASH32,
    EMPTY_SHA3,
    SLASH_WALLET_ADDRESS,
    NUMBER_OF_HEAD_HASH_TO_SAVE,
    TIME_BETWEEN_HEAD_HASH_SAVE,

    COLLATION_SIZE)

import pickle
from solc import compile_files

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
from helios.dev_tools import create_dev_test_random_blockchain_database
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

from hvm.utils.profile import profile

from hvm.constants import random_private_keys
from hvm.vm.forks.helios_testnet.blocks import HeliosMicroBlock, HeliosTestnetBlock





def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(random_private_keys[instance_number])

SENDER = TESTNET_GENESIS_PRIVATE_KEY
RECEIVER = get_primary_node_private_helios_key(1)
RECEIVER2 = get_primary_node_private_helios_key(2)
RECEIVER3 = get_primary_node_private_helios_key(3)
RECEIVER4 = get_primary_node_private_helios_key(4)


def ensure_chronological_block_hashes_are_fully_synced(base_db_1, base_db_2):
    node_1 = TestnetChain(base_db_1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    node_2 = TestnetChain(base_db_2, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    node_1_chain_head_root_hash_timestamp = node_1.chain_head_db.get_historical_root_hashes()[-1]
    node_2_chain_head_root_hash_timestamp = node_2.chain_head_db.get_historical_root_hashes()[-1]
    assert (node_1_chain_head_root_hash_timestamp == node_2_chain_head_root_hash_timestamp)

def ensure_chronological_block_hashes_are_identical(base_db_1, base_db_2):
    node_1 = TestnetChain(base_db_1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    node_2 = TestnetChain(base_db_2, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    node_1_chain_head_root_hash_timestamps = node_1.chain_head_db.get_historical_root_hashes()
    node_2_chain_head_root_hash_timestamps = node_2.chain_head_db.get_historical_root_hashes()
    assert (node_1_chain_head_root_hash_timestamps == node_2_chain_head_root_hash_timestamps)


def ensure_blockchain_databases_identical(base_db_1, base_db_2):
    node_1 = TestnetChain(base_db_1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    node_2 = TestnetChain(base_db_2, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    # Get all of the addresses of every chain
    next_head_hashes = node_1.chain_head_db.get_head_block_hashes_list()

    wallet_addresses = []
    for next_head_hash in next_head_hashes:
        chain_address = node_1.chaindb.get_chain_wallet_address_for_block_hash(next_head_hash)
        wallet_addresses.append(chain_address)

    next_head_hashes_node_2 = node_2.chain_head_db.get_head_block_hashes_list()

    # This gaurantees both have all the same chains
    assert (next_head_hashes == next_head_hashes_node_2)

    for wallet_address in wallet_addresses:

        # Compare all properties of each account with the hashes
        node_1_account_hash = node_1.get_vm().state.account_db.get_account_hash(wallet_address)
        node_2_account_hash = node_2.get_vm().state.account_db.get_account_hash(wallet_address)
        assert (node_1_account_hash == node_2_account_hash)

        # Compare all chains in database
        node_1_chain = node_1.get_all_blocks_on_chain(wallet_address)
        node_2_chain = node_2.get_all_blocks_on_chain(wallet_address)
        assert (node_1_chain == node_2_chain)

        # Compare the blocks at a deeper level
        for i in range(len(node_1_chain)):
            assert (node_1_chain[i].hash == node_2_chain[i].hash)
            assert_var_1 = node_1.chaindb.get_all_descendant_block_hashes(node_1_chain[i].hash)
            assert_var_2 = node_2.chaindb.get_all_descendant_block_hashes(node_2_chain[i].hash)
            assert ( assert_var_1==assert_var_2 )


def compile_sol_and_save_to_file(solidity_file, output_file):
    compiled_sol = compile_files([solidity_file])
    print("writing compiled code dictionary with keys {}".format(compiled_sol.keys()))
    f = open(output_file, "wb")
    pickle.dump(compiled_sol, f)
    f.close()

def load_compiled_sol_dict(compiled_file_location):
    pickle_in = open(compiled_file_location, "rb")
    compiled_sol_dict = pickle.load(pickle_in)
    return compiled_sol_dict

W3_TX_DEFAULTS = {'gas': 0, 'gasPrice': 0, 'chainId': 0}

def ensure_chronological_chain_matches_canonical(chain):
    #
    # This function will be time consuming if we have a full length chronoligical chain
    #

    dummy_chain = TestnetChain(chain.db, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    dummy_chain.enable_read_only_db()
    dummy_chain.initialize_historical_root_hashes_and_chronological_blocks()

    earliest_window = chain.chain_head_db.earliest_window
    historical_root_hashes_chain = chain.chain_head_db.get_historical_root_hashes()
    historical_root_hashes_dummy_chain = dummy_chain.chain_head_db.get_historical_root_hashes()
    historical_root_hashes_dummy_chain_dict = dict(historical_root_hashes_dummy_chain)


    # The dummy one can have more in the past and future. But any that the original chain has must be the same. so lets iter over that one
    for historical_root_hash_timestamp in historical_root_hashes_chain:
        timestamp = historical_root_hash_timestamp[0]
        root_hash = historical_root_hash_timestamp[1]
        if timestamp <= earliest_window:
            continue

        assert(historical_root_hashes_dummy_chain_dict[timestamp] == root_hash)

        chronological_blocks_chain = chain.chain_head_db.load_chronological_block_window(timestamp)
        chronological_blocks_dummy_chain = dummy_chain.chain_head_db.load_chronological_block_window(timestamp)

        assert(chronological_blocks_chain == chronological_blocks_dummy_chain), "{} | {}".format(chronological_blocks_chain, chronological_blocks_dummy_chain)

    # also, the newest historical root hash must be the same
    assert(historical_root_hashes_chain[-1] == historical_root_hashes_dummy_chain[-1])


    