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
    GAS_TX, BLOCK_TIMESTAMP_FUTURE_ALLOWANCE,
    NUMBER_OF_HEAD_HASH_TO_SAVE, BLOCK_GAS_LIMIT)

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
    ensure_chronological_block_hashes_are_identical,
    ensure_chronological_chain_matches_canonical)

from hvm.exceptions import ParentNotFound

def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(random_private_keys[instance_number])

SENDER = TESTNET_GENESIS_PRIVATE_KEY
RECEIVER = get_primary_node_private_helios_key(1)
RECEIVER2 = get_primary_node_private_helios_key(2)
RECEIVER3 = get_primary_node_private_helios_key(3)
RECEIVER4 = get_primary_node_private_helios_key(4)
RECEIVER5 = get_primary_node_private_helios_key(5)


# #TODO fix this test. need to get coin mature time from vm
# def test_block_children_stake_calculation():
#     if COIN_MATURE_TIME_FOR_STAKING <= 5:
#         #    0-------------------------0    total stake should be receiver 1, 2, 3, 4 = 1+1+10000000000-21001-21000+0 = 9999979002
#         #      \ \      \             /
#         #       \ ---1   --3--       /
#         #        ----2        \     /
#         #                      ---4/
#
#         testdb = MemoryDB()
#         sender_chain = TestnetChain.from_genesis(testdb, SENDER.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)
#
#
#
#         current_genesis_chain_head_number = sender_chain.chaindb.get_canonical_head(SENDER.public_key.to_canonical_address()).block_number
#
#         assert(current_genesis_chain_head_number == 0)
#         genesis_chain_next_head_block_number = sender_chain.header.block_number
#         assert (genesis_chain_next_head_block_number == current_genesis_chain_head_number + 1)
#
#         """
#         Send 2 blocks
#         """
#         sender_chain = TestnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)
#         sender_chain.create_and_sign_transaction_for_queue_block(
#                     gas_price=0x01,
#                     gas=0x0c3500,
#                     to=RECEIVER.public_key.to_canonical_address(),
#                     value=1,
#                     data=b"",
#                     v=0,
#                     r=0,
#                     s=0
#                     )
#
#         sender_chain.create_and_sign_transaction_for_queue_block(
#                 gas_price=0x01,
#                 gas=0x0c3500,
#                 to=RECEIVER2.public_key.to_canonical_address(),
#                 value=1,
#                 data=b"",
#                 v=0,
#                 r=0,
#                 s=0
#                 )
#
#         sender_chain.import_current_queue_block()
#
#         current_genesis_chain_head_number = sender_chain.chaindb.get_canonical_head(SENDER.public_key.to_canonical_address()).block_number
#         assert (current_genesis_chain_head_number == 1)
#         genesis_chain_next_head_block_number = sender_chain.header.block_number
#         assert (genesis_chain_next_head_block_number == current_genesis_chain_head_number + 1)
#
#         """
#         Receive all tx in one block - genesis block must receive
#         """
#         receiver_chain = TestnetChain(testdb, RECEIVER.public_key.to_canonical_address(), RECEIVER)
#         receiver_chain.populate_queue_block_with_receive_tx()
#         receiver_chain.import_current_queue_block()
#
#         receiver2_chain = TestnetChain(testdb, RECEIVER2.public_key.to_canonical_address(), RECEIVER2)
#         receiver2_chain.populate_queue_block_with_receive_tx()
#         receiver2_chain.import_current_queue_block()
#
#
#         sender_chain = TestnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)
#         sender_chain.create_and_sign_transaction_for_queue_block(
#                     gas_price=0x01,
#                     gas=0x0c3500,
#                     to=RECEIVER3.public_key.to_canonical_address(),
#                     value=10000000000,
#                     data=b"",
#                     v=0,
#                     r=0,
#                     s=0
#                     )
#
#
#         sender_chain.import_current_queue_block()
#
#         current_genesis_chain_head_number = sender_chain.chaindb.get_canonical_head(SENDER.public_key.to_canonical_address()).block_number
#         assert (current_genesis_chain_head_number == 2)
#         genesis_chain_next_head_block_number = sender_chain.header.block_number
#         assert (genesis_chain_next_head_block_number == current_genesis_chain_head_number + 1)
#
#
#         receiver3_chain = TestnetChain(testdb, RECEIVER3.public_key.to_canonical_address(), RECEIVER3)
#         receiver3_chain.populate_queue_block_with_receive_tx()
#         receiver3_chain.import_current_queue_block()
#
#
#         receiver3_chain = TestnetChain(testdb, RECEIVER3.public_key.to_canonical_address(), RECEIVER3)
#         receiver3_chain.create_and_sign_transaction_for_queue_block(
#                     gas_price=0x01,
#                     gas=0x0c3500,
#                     to=RECEIVER4.public_key.to_canonical_address(),
#                     value=21001,
#                     data=b"",
#                     v=0,
#                     r=0,
#                     s=0
#                     )
#
#
#         receiver3_chain.import_current_queue_block()
#
#         receiver4_chain = TestnetChain(testdb, RECEIVER4.public_key.to_canonical_address(), RECEIVER4)
#         receiver4_chain.populate_queue_block_with_receive_tx()
#         receiver4_chain.import_current_queue_block()
#
#         receiver4_chain = TestnetChain(testdb, RECEIVER4.public_key.to_canonical_address(), RECEIVER4)
#         receiver4_chain.create_and_sign_transaction_for_queue_block(
#             gas_price=0x01,
#             gas=21000,
#             to=RECEIVER5.public_key.to_canonical_address(),
#             value=1,
#             data=b"",
#             v=0,
#             r=0,
#             s=0
#         )
#
#         receiver4_chain.import_current_queue_block()
#
#         time.sleep(COIN_MATURE_TIME_FOR_STAKING+1)
#
#         print("getting balance of receiver2")
#         # print(receiver2_chain.get_vm().state.account_db.get_balance(receiver2_chain.wallet_address))
#         print("getting current stake")
#         assert(receiver_chain.get_mature_stake() == 1), "{}".format(receiver_chain.get_mature_stake())
#         assert(receiver2_chain.get_mature_stake() == 1), "{}".format(receiver2_chain.get_mature_stake())
#         assert(receiver3_chain.get_mature_stake() == 10000000000-21001-21000), "{}".format(receiver3_chain.get_mature_stake())
#         assert(receiver4_chain.get_mature_stake() == 0), "{}".format(receiver4_chain.get_mature_stake())
#
#         #lets get the children stake of the genesis block
#         genesis_block_hash = sender_chain.chaindb.get_canonical_block_hash(0, SENDER.public_key.to_canonical_address())
#         assert(receiver4_chain.chaindb.get_block_stake_from_children(genesis_block_hash, int(time.time())) == 9999958001), "{}".format(receiver_chain.chaindb.get_block_stake_from_children(genesis_block_hash,int(time.time())))
#
#         print("All stake maturity tests passed")
#         print("All block children stake test passed")

# test_block_children_stake_calculation()
# sys.exit()


def test_chronological_block_window_stake():
    testdb = MemoryDB()
    sender_chain = TestnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)
    coin_mature_time_for_staking = sender_chain.get_vm(timestamp = Timestamp(int(time.time()))).consensus_db.coin_mature_time_for_staking
    chronological_block_window_start = int((time.time()-coin_mature_time_for_staking*2)/TIME_BETWEEN_HEAD_HASH_SAVE)*TIME_BETWEEN_HEAD_HASH_SAVE-TIME_BETWEEN_HEAD_HASH_SAVE*4
    genesis_block_time = int(chronological_block_window_start-TIME_BETWEEN_HEAD_HASH_SAVE/2)
    transactions_start_time = chronological_block_window_start+TIME_BETWEEN_HEAD_HASH_SAVE/2

    chronological_block_window_two_start = chronological_block_window_start+TIME_BETWEEN_HEAD_HASH_SAVE
    transactions_start_time_two = chronological_block_window_two_start+TIME_BETWEEN_HEAD_HASH_SAVE/2



    genesis_params, genesis_state = create_new_genesis_params_and_state(TESTNET_GENESIS_PRIVATE_KEY, to_wei(100000000, 'ether'), genesis_block_time)

    time_between_blocks = max(MIN_TIME_BETWEEN_BLOCKS,1)
    # import genesis block
    TestnetChain.from_genesis(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), genesis_params, genesis_state)

    tx_list = [[TESTNET_GENESIS_PRIVATE_KEY, RECEIVER, to_wei(10000000, 'ether'), transactions_start_time],
               [TESTNET_GENESIS_PRIVATE_KEY, RECEIVER2, to_wei(10000000, 'ether'), transactions_start_time + time_between_blocks],
               [TESTNET_GENESIS_PRIVATE_KEY, RECEIVER3, to_wei(10000000, 'ether'), transactions_start_time + time_between_blocks * 2],
               [RECEIVER, RECEIVER4, to_wei(1000000, 'ether'), transactions_start_time+time_between_blocks*3],
               [RECEIVER, RECEIVER3, to_wei(1000000, 'ether'), transactions_start_time+time_between_blocks*4],

               [RECEIVER, RECEIVER3, to_wei(100000, 'ether'), transactions_start_time_two+time_between_blocks*1],
               [RECEIVER3, RECEIVER4, to_wei(500000, 'ether'), transactions_start_time_two+time_between_blocks*2]]

    add_transactions_to_blockchain_db(testdb, tx_list)

    sender_chain = TestnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)


    # check the normal get_mature_stake function is working
    expected_genesis_stake_1_time = int(genesis_block_time + coin_mature_time_for_staking)
    expected_genesis_stake_1 = to_wei(100000000, 'ether')
    expected_genesis_stake_2_time = int(transactions_start_time+time_between_blocks+coin_mature_time_for_staking)
    expected_genesis_stake_2 = to_wei((100000000-10000000-10000000), 'ether')-to_wei(GAS_TX, 'gwei') - to_wei(GAS_TX, 'gwei')
    expected_genesis_stake_3 = to_wei((100000000 - 10000000 - 10000000 - 10000000), 'ether') - to_wei(GAS_TX, 'gwei') - to_wei(GAS_TX, 'gwei') -to_wei(GAS_TX, 'gwei')
    
    assert(sender_chain.chaindb.get_mature_stake(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), coin_mature_time_for_staking, expected_genesis_stake_1_time) == expected_genesis_stake_1)
    assert(sender_chain.chaindb.get_mature_stake(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), coin_mature_time_for_staking, expected_genesis_stake_2_time) == expected_genesis_stake_2)
    assert(sender_chain.chaindb.get_mature_stake(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), coin_mature_time_for_staking) == expected_genesis_stake_3)
    
    expected_mature_stake_1 = (sender_chain.chaindb.get_mature_stake(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), coin_mature_time_for_staking) +
                               sender_chain.chaindb.get_mature_stake(RECEIVER.public_key.to_canonical_address(), coin_mature_time_for_staking) +
                               sender_chain.chaindb.get_mature_stake(RECEIVER2.public_key.to_canonical_address(), coin_mature_time_for_staking) +
                               sender_chain.chaindb.get_mature_stake(RECEIVER3.public_key.to_canonical_address(), coin_mature_time_for_staking) +
                               sender_chain.chaindb.get_mature_stake(RECEIVER4.public_key.to_canonical_address(), coin_mature_time_for_staking)
                               )


    expected_mature_stake_2_time = int(transactions_start_time+time_between_blocks*2+coin_mature_time_for_staking)
    expected_mature_stake_2 = (
            sender_chain.chaindb.get_mature_stake(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), coin_mature_time_for_staking, expected_mature_stake_2_time) +
            sender_chain.chaindb.get_mature_stake(RECEIVER.public_key.to_canonical_address(), coin_mature_time_for_staking,expected_mature_stake_2_time) +
            sender_chain.chaindb.get_mature_stake(RECEIVER2.public_key.to_canonical_address(), coin_mature_time_for_staking,expected_mature_stake_2_time) +
            sender_chain.chaindb.get_mature_stake(RECEIVER3.public_key.to_canonical_address(), coin_mature_time_for_staking,expected_mature_stake_2_time)
                )


    expected_mature_stake_3 = (
            sender_chain.chaindb.get_mature_stake(RECEIVER.public_key.to_canonical_address(), coin_mature_time_for_staking) +
            sender_chain.chaindb.get_mature_stake(RECEIVER3.public_key.to_canonical_address(), coin_mature_time_for_staking) +
            sender_chain.chaindb.get_mature_stake(RECEIVER4.public_key.to_canonical_address(), coin_mature_time_for_staking)
    )

    expected_mature_stake_4_time = int(transactions_start_time_two+time_between_blocks*1 + coin_mature_time_for_staking)
    expected_mature_stake_4 = (
            sender_chain.chaindb.get_mature_stake(RECEIVER.public_key.to_canonical_address(), coin_mature_time_for_staking, expected_mature_stake_4_time) +
            sender_chain.chaindb.get_mature_stake(RECEIVER3.public_key.to_canonical_address(), coin_mature_time_for_staking, expected_mature_stake_4_time) +
            sender_chain.chaindb.get_mature_stake(RECEIVER4.public_key.to_canonical_address(), coin_mature_time_for_staking, expected_mature_stake_4_time)
    )

    # now we test that it is correctly calculating it for the window
    assert(sender_chain.get_mature_stake_for_chronological_block_window(chronological_block_window_start)==expected_mature_stake_1)
    assert (sender_chain.get_mature_stake_for_chronological_block_window(chronological_block_window_start, expected_mature_stake_2_time) == expected_mature_stake_2)
    assert (sender_chain.get_mature_stake_for_chronological_block_window(chronological_block_window_two_start) == expected_mature_stake_3)
    assert (sender_chain.get_mature_stake_for_chronological_block_window(chronological_block_window_two_start, expected_mature_stake_4_time) == expected_mature_stake_4)


def test_send_transaction_then_receive():
    # testdb = LevelDB('/home/tommy/.local/share/helios/chain/full27')
    testdb = MemoryDB()
    sender_chain = TestnetChain.from_genesis(testdb, SENDER.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS,
                                             TESTNET_GENESIS_STATE)
    """
    Send 2 blocks
    """

    genesis_block_header = sender_chain.chaindb.get_canonical_block_header_by_number(0, SENDER.public_key.to_canonical_address())
    print('checking signature validity')
    print(genesis_block_header.is_signature_valid)

    sender_chain = TestnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)

    print('initial root_hash = ', sender_chain.chain_head_db.get_root_hash())
    print(sender_chain.chain_head_db.get_historical_root_hashes())
    # exit()

    vm = sender_chain.get_vm()
    print('initial balance = ', vm.state.account_db.get_balance(SENDER.public_key.to_canonical_address()))
    vm.state.account_db.delta_balance(SENDER.public_key.to_canonical_address(), 5)
    print('balance after delta= ', vm.state.account_db.get_balance(SENDER.public_key.to_canonical_address()))
    vm.state = vm.get_state_class()(
        db=vm.chaindb.db,
        execution_context=vm.block.header.create_execution_context()
    )
    print('balance after state refresh = ', vm.state.account_db.get_balance(SENDER.public_key.to_canonical_address()))
    # exit()

    tx = sender_chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=0x0c3500,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    sender_chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=0x0c3500,
        to=RECEIVER2.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )


    # print('initial root_hash = ',sender_chain.chain_head_db.get_root_hash())
    # print(sender_chain.chain_head_db.get_historical_root_hashes())
    balance_1 = sender_chain.get_vm().state.account_db.get_balance(SENDER.public_key.to_canonical_address())
    print('BALANCE BEFORE SENDING TX = ', balance_1)
    sender_block_1_imported = sender_chain.import_current_queue_block()
    balance_2 = sender_chain.get_vm().state.account_db.get_balance(SENDER.public_key.to_canonical_address())
    print('BALANCE AFTER SENDING TX = ', balance_2)
    assert ((balance_1 - balance_2) == (tx.intrinsic_gas * 2 + 2))
    print("Passed gas and balance test")


    min_time_between_blocks = sender_chain.get_vm(timestamp = Timestamp(int(time.time()))).min_time_between_blocks
    print("waiting {} seconds before we can import the next block".format(min_time_between_blocks))
    time.sleep(min_time_between_blocks)
    sender_chain = TestnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)
    sender_chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=0x0c3500,
        to=RECEIVER.public_key.to_canonical_address(),
        value=10000000,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    sender_chain.import_current_queue_block()

    """
    Receive all tx in one block - genesis block must receive
    """
    receiver_chain = TestnetChain(testdb, RECEIVER.public_key.to_canonical_address(), RECEIVER)
    receiver_chain.populate_queue_block_with_receive_tx()
    block_0_imported = receiver_chain.import_current_queue_block()


    #
    # Make sure we find the receive tx using get_receive_tx_from_send_tx()
    #
    receive_tx = receiver_chain.get_receive_tx_from_send_tx(tx.hash)
    assert(block_0_imported.receive_transactions[0] == receive_tx)
    print("get_receive_tx_from_send_tx test passed")

    receiver2_chain = TestnetChain(testdb, RECEIVER2.public_key.to_canonical_address(), RECEIVER2)
    receiver2_chain.populate_queue_block_with_receive_tx()
    receiver2_chain.import_current_queue_block()

    # there should be 3 chians now. Lets make sure there are 3 saved head hashes in the chain_head_db database
    chain_head_root_hash = receiver_chain.chain_head_db.get_latest_historical_root_hash()[1]
    block_hashes = receiver_chain.chain_head_db.get_head_block_hashes_list(chain_head_root_hash)
    assert (len(block_hashes) == 3)
    print('passed head hash count test')

    #    #####
    #    head_hash = receiver_chain.chaindb.get_canonical_head_hash(wallet_address = RECEIVER.public_key.to_canonical_address())
    #    print('before {}'.format(head_hash))
    #    receiver_chain.enable_journal_db()
    #    journal_record = receiver_chain.record_journal()


    print("Imported block timestamp = {}".format(block_0_imported.header.timestamp))
    print("waiting {} seconds before we can import the next block".format(min_time_between_blocks))
    time.sleep(min_time_between_blocks)

    receiver_chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=0x0c3500,
        to=SENDER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )
    print("Queue block timestamp = {}".format(receiver_chain.queue_block.header.timestamp))


    block_1_imported = receiver_chain.import_current_queue_block()

    print("checking that block account_balance matches account_db. Expected = {}".format(
        block_1_imported.header.account_balance))
    assert (block_1_imported.header.account_balance == receiver_chain.get_vm().state.account_db.get_balance(
        RECEIVER.public_key.to_canonical_address()))

    # print("block 1 parent hash = ", encode_hex(block_1_imported.header.parent_hash))
    # print("length in bytes = ", len(block_1_imported.header.parent_hash))
    # sys.exit()
    print('testtest2')

    historical_root_hashes = receiver_chain.chain_head_db.get_historical_root_hashes()
    print(receiver_chain.chain_head_db.root_hash)
    print(historical_root_hashes[-1][1])

    """
    send and receive in same block
    """

    sender_chain = TestnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)
    sender_chain.populate_queue_block_with_receive_tx()
    sender_chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=0x0c3500,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1000,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    sender_block = sender_chain.import_current_queue_block()

    print("checking that block account_balance matches account_db. Expected = {}".format(
        sender_block.header.account_balance))
    assert (sender_block.header.account_balance == sender_chain.get_vm().state.account_db.get_balance(
        SENDER.public_key.to_canonical_address()))

    """
    make sure we can receive
    """

    receiver_chain = TestnetChain(testdb, RECEIVER.public_key.to_canonical_address(), RECEIVER)
    print('testtest3')
    historical_root_hashes = receiver_chain.chain_head_db.get_historical_root_hashes()
    print(receiver_chain.chain_head_db.root_hash)
    print(historical_root_hashes[-1][1])

    print("Imported block timestamp = {}".format(block_0_imported.header.timestamp))
    print("waiting {} seconds before we can import the next block".format(min_time_between_blocks))
    time.sleep(min_time_between_blocks)

    receiver_chain.populate_queue_block_with_receive_tx()
    block_2_imported = receiver_chain.import_current_queue_block()

    print("checking that block account_balance matches account_db. Expected = {}".format(
        block_2_imported.header.account_balance))
    assert (block_2_imported.header.account_balance == receiver_chain.get_vm().state.account_db.get_balance(
        RECEIVER.public_key.to_canonical_address()))

    print("Checking that imported blocks are the same as blocks retreived from DB")
    block_0_from_db = receiver_chain.get_block_by_number(0)
    block_1_from_db = receiver_chain.get_block_by_number(1)
    block_2_from_db = receiver_chain.get_block_by_number(2)
    sender_block_1_from_db = receiver_chain.get_block_by_number(1, chain_address = SENDER.public_key.to_canonical_address())

    assert (block_0_imported.header.account_hash == block_0_from_db.header.account_hash)

    assert (block_0_imported == block_0_from_db)
    assert (block_1_imported == block_1_from_db)
    assert (block_2_imported == block_2_from_db)
    assert (sender_block_1_imported == sender_block_1_from_db)

    print("Passed test")

    print("printing entire receiver chain")
    all_blocks = receiver_chain.get_all_blocks_on_chain()
    print(all_blocks)

    print("printing head hashes")
    print(list(receiver_chain.chain_head_db.get_head_block_hashes()))
    # exit()

    """
    check that account hash in the database matches that on the canonical head
    """
    account_hash = sender_chain.get_vm().state.account_db.get_account_hash(sender_chain.wallet_address)
    print('account_hash in database', account_hash)
    account_hash_on_block = sender_chain.get_canonical_head().account_hash
    print("account_hash on canonical head", account_hash_on_block)
    assert(account_hash == account_hash_on_block)

    """
    check that the head hashes are correctly saved:
    """
    sender_head = sender_chain.get_canonical_head()
    print("sender head hash = {}".format(sender_head.hash))
    print("sender head hash from chain head hash trie = {}".format(
        receiver_chain.chain_head_db.get_chain_head_hash(sender_chain.wallet_address)))

    receiver_head = receiver_chain.get_canonical_head()
    print("receiver head hash = {}".format(receiver_head.hash))
    print("receiver head hash from chain head hash trie = {}".format(
        receiver_chain.chain_head_db.get_chain_head_hash(receiver_chain.wallet_address)))

    # now lets load the historical head hashes
    historical_root_hashes = receiver_chain.chain_head_db.get_historical_root_hashes()
    hist_root_hash_int = [[x[0], x[1]] for x in historical_root_hashes]
    print(hist_root_hash_int)
    # test to make sure they are in order and have the correct spacing
    for i in range(1, len(hist_root_hash_int)):
        if hist_root_hash_int[i - 1][0] != hist_root_hash_int[i][0] - TIME_BETWEEN_HEAD_HASH_SAVE:
            print("fail")

    print('testtest4')
    print(receiver_chain.chain_head_db.root_hash)
    print(historical_root_hashes[-1][1])
    assert (receiver_chain.chain_head_db.root_hash == historical_root_hashes[-1][1])

    # try retreiving a block at a timestamp
    # block_hash_at_timestamp = receiver_chain.chain_head_db.get_chain_head_hash_at_timestamp(sender_chain.wallet_address, 1509021000)
    # print(block_hash_at_timestamp)
    # print('printing chronological blocks')
    # chronological_blocks = receiver_chain.chain_head_db.load_chronological_block_window(1529096000)
    # print([[x[0]] for x in chronological_blocks])
    # print(chronological_blocks)
    print("getting current stake")
    current_stake = receiver_chain.get_mature_stake()
    print(current_stake)

    # lets get the children stake of the genesis block
    genesis_block_hash = sender_chain.chaindb.get_canonical_block_hash(0, SENDER.public_key.to_canonical_address())
    print("genesis block hash", genesis_block_hash)
    stake_from_children = receiver_chain.chaindb.get_block_stake_from_children(genesis_block_hash, int(time.time()))
    sender_chain.chaindb.get_block_stake_from_children(genesis_block_hash, int(time.time()))
    print("printing genesis block children stake")
    print(stake_from_children)

    print("trying to load root hash timestamps after given time")
    print(sender_chain.chain_head_db.get_historical_root_hashes(after_timestamp=time.time()))

    print(receiver_chain.chain_head_db.get_historical_root_hash(int(time.time()) + 1000))


#
# test_send_transaction_then_receive()
# sys.exit()

def import_chain(testdb1, testdb2):
    '''
    Node 2 with testdb2 imports chains from node 1 with testdb1
    :param testdb1:
    :param testdb2:
    :return:
    '''
    node_1 = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    next_head_hashes = node_1.chain_head_db.get_next_n_head_block_hashes(ZERO_HASH32, 0, 99999)
    print("IMPORTING {} CHAINS".format(len(next_head_hashes)))


    for next_head_hash in next_head_hashes:
        chain_address = node_1.chaindb.get_chain_wallet_address_for_block_hash(next_head_hash)

        chain_to_import = node_1.get_all_blocks_on_chain(chain_address)

        node_2 = TestnetChain(testdb2, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
        node_2.import_chain(block_list=chain_to_import)


    ensure_blockchain_databases_identical(testdb1, testdb2)
    ensure_chronological_block_hashes_are_identical(testdb1, testdb2)

def _test_import_unprocessed_blocks(base_db = None):

    testdb1 = create_dev_test_random_blockchain_db_with_reward_blocks(base_db = base_db, num_iterations=30)
    testdb2 = MemoryDB()

    node_1 = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    node_2 = TestnetChain.from_genesis(testdb2, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                                       TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    chain_head_hashes = node_1.chain_head_db.get_head_block_hashes_list()

    chains = []
    for head_hash in chain_head_hashes:
        chain = node_1.get_all_blocks_on_chain_by_head_block_hash(head_hash)
        chains.append(chain)

    random.shuffle(chains)

    for chain in chains:
        node_2.import_chain(chain)

    ensure_blockchain_databases_identical(testdb1, testdb2)
    ensure_chronological_block_hashes_are_identical(testdb1, testdb2)

def test_import_unprocessed_blocks():
    '''
    We generate random blockchain databases that include transactions, send transactions, reward blocks.
    Then we import the chains in random order. Do this enough times and we will have seen all possible cases.
    :return:
    '''

    # 1) Create random blockchain db with rewards.
    # 2) Import blocks randomly.
    # 3) Do this many times to ensure we import in all possible orders to test all scenarios

    for i in range(15):
        _test_import_unprocessed_blocks()



# test_import_unprocessed_blocks()
# exit()


def test_import_chain():
    # Where node 2 doesn't have any blocks other than genesis
    testdb1 = MemoryDB()
    testdb2 = MemoryDB()

    create_dev_test_random_blockchain_database(testdb1)
    TestnetChain.from_genesis(testdb2, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    import_chain(testdb1, testdb2)

    # Where node 1 and node 2 have different blockchain databases

    testdb1 = MemoryDB()
    testdb2 = MemoryDB()

    create_dev_test_random_blockchain_database(testdb1)
    create_dev_test_random_blockchain_database(testdb2)

    import_chain(testdb1, testdb2)

    # Where node 2 continuously imports new databases

    testdb2 = MemoryDB()
    create_dev_test_random_blockchain_database(testdb2)

    for i in range(5):
        testdb1 = MemoryDB()
        create_dev_test_random_blockchain_database(testdb1)

        import_chain(testdb1, testdb2)


#test_import_chain()


# def import_chronological_block_window(testdb1, testdb2):
#
#     node_1 = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
#     node_2 = TestnetChain(testdb2, RECEIVER.public_key.to_canonical_address(), RECEIVER)
#
#     node_1_historical_root_hashes = node_1.chain_head_db.get_historical_root_hashes()
#
#     for timestamp_root_hash in node_1_historical_root_hashes:
#         print("Importing chronological block window for timestamp {}".format(timestamp_root_hash[0]))
#         # timestamp of chronological that we are importing: node_1_historical_root_hashes[-2][0]
#         chronological_blocks = node_1.get_all_chronological_blocks_for_window(timestamp_root_hash[0])
#
#         # make sure propogate_block_head_hash_timestamp_to_present = True and False works
#         node_2.import_chronological_block_window(chronological_blocks, timestamp_root_hash[0])
#
#     ensure_blockchain_databases_identical(testdb1, testdb2)
#     ensure_chronological_block_hashes_are_identical(testdb1, testdb2)


# def test_import_chronolgical_block_windows():
#     # Where node 2 has no blocks other than genesis block on genesis chain
#     testdb1 = MemoryDB()
#     testdb2 = MemoryDB()
#
#     create_dev_test_random_blockchain_database(testdb1)
#     chain_1 = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
#
#     chain_2 = TestnetChain.from_genesis(testdb2, RECEIVER.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)
#
#     # print('AAAAAAAAAAAAAAA')
#     # print(encode_hex(chain_1.genesis_wallet_address))
#     # print(chain_1.chaindb.get_canonical_block_header_by_number(0, chain_1.genesis_wallet_address))
#     # print(chain_2.chaindb.get_canonical_block_header_by_number(0, chain_2.genesis_wallet_address))
#     import_chronological_block_window(testdb1, testdb2)
#
#     # Where node 2 has a different blockchain database. This requires overwriting.
#     testdb1 = MemoryDB()
#     testdb2 = MemoryDB()
#
#     create_dev_test_random_blockchain_database(testdb1)
#     create_dev_test_random_blockchain_database(testdb2)
#
#
#     import_chronological_block_window(testdb1, testdb2)

# test_import_chronolgical_block_windows()


#TODO: add some refund transaction tests
# add reward bundle tests
def test_importing_p2p_type_block():
    from hvm.rlp.sedes import (
        hash32
    )
    import rlp_cython as rlp
    from rlp_cython import sedes
    from hvm.rlp.transactions import BaseTransaction
    from helios.rlp_templates.hls import P2PSendTransaction, P2PReceiveTransaction, P2PBlock
    from hvm.rlp.consensus import StakeRewardBundle
    from hvm.rlp.blocks import BaseBlock
    from hvm.rlp.transactions import BaseTransaction, BaseReceiveTransaction

    testdb1 = MemoryDB()
    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    transactions = []
    for i in range(5):
        transaction = P2PSendTransaction(
            nonce=i+1,
            gas_price=0x01,
            gas=0x0c3500,
            to=RECEIVER.public_key.to_canonical_address(),
            value=0x01,
            data=b"",
            v=0,
            r=0,
            s=0
        )
        transactions.append(transaction)

    receive_transactions = []
    for i in range(5):
        receive_transaction = P2PReceiveTransaction(sender_block_hash=ZERO_HASH32,
                                                    send_transaction_hash=ZERO_HASH32,
                                                    is_refund = False,
                                                    remaining_refund = 0)
        receive_transactions.append(receive_transaction)

    reward_bundle = StakeRewardBundle()

    block = P2PBlock(chain.header, transactions, receive_transactions, reward_bundle)

    converted_block = chain.get_vm().convert_block_to_correct_class(block)

    assert(isinstance(converted_block, BaseBlock))

    for tx in converted_block.transactions:
        assert(isinstance(tx, BaseTransaction))

    for tx in converted_block.receive_transactions:
        assert(isinstance(tx, BaseReceiveTransaction))

    assert(isinstance(reward_bundle, StakeRewardBundle))

# test_importing_p2p_type_block()

def test_import_invalid_transaction_duplicate_nonce():
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    print('First nonce =',valid_block.transactions[0].nonce)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=2,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    block_with_same_nonse_transaction = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    block_with_same_nonse_transaction = block_with_same_nonse_transaction.copy(
        header = block_with_same_nonse_transaction.header.copy(
            parent_hash=valid_block.hash,
            block_number=2).get_signed(TESTNET_GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    print('Second nonce =', block_with_same_nonse_transaction.transactions[0].nonce)
    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    chain.import_block(valid_block)
    with pytest.raises(ValidationError):
        chain.import_block(block_with_same_nonse_transaction)

def test_import_invalid_transaction_nonce_too_great():
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    # import a second block to increase tx nonce
    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=2,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    min_time_between_blocks = dummy_chain.get_vm(timestamp=Timestamp(int(time.time()))).min_time_between_blocks
    print("waiting {} seconds before we can import the next block".format(min_time_between_blocks))
    time.sleep(min_time_between_blocks)

    invalid_block = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    invalid_block = invalid_block.copy(
        header = invalid_block.header.copy(
            parent_hash=valid_block.header.parent_hash,
            block_number=1).get_signed(TESTNET_GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    print('Second nonce =', invalid_block.transactions[0].nonce)

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)


def test_import_invalid_block_wrong_parent_hash():
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    print('First nonce =',valid_block.transactions[0].nonce)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=2,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    block_with_same_nonse_transaction = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    block_with_same_nonse_transaction = block_with_same_nonse_transaction.copy(
        header = block_with_same_nonse_transaction.header.copy(
            parent_hash=valid_block.hash,
            block_number=1).get_signed(TESTNET_GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    chain.import_block(valid_block)
    with pytest.raises(ValidationError):
        chain.import_block(block_with_same_nonse_transaction)


def test_import_invalid_block_gas_limit_too_small():
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    invalid_block = valid_block.copy(
        header = valid_block.header.copy(
            gas_limit=5
        ).get_signed(TESTNET_GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_gas_limit_too_large():
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    invalid_block = valid_block.copy(
        header = valid_block.header.copy(
            gas_limit=99999999999999999
        ).get_signed(TESTNET_GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_incorrect_account_hash():
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    invalid_block = valid_block.copy(
        header = valid_block.header.copy(
            account_hash=keccak(int_to_big_endian(random.randint(1000000,10000000)))
        ).get_signed(TESTNET_GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_incorrect_account_balance():
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    invalid_block = valid_block.copy(
        header = valid_block.header.copy(
            account_balance=100000000000
        ).get_signed(TESTNET_GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_incorrect_transaction_root():
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    invalid_block = valid_block.copy(
        header = valid_block.header.copy(
            transaction_root=keccak(int_to_big_endian(random.randint(1000000,10000000)))
        ).get_signed(TESTNET_GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_incorrect_receive_transaction_root():
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    invalid_block = valid_block.copy(
        header = valid_block.header.copy(
            receive_transaction_root=keccak(int_to_big_endian(random.randint(1000000,10000000)))
        ).get_signed(TESTNET_GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_incorrect_receipt_root():
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    invalid_block = valid_block.copy(
        header = valid_block.header.copy(
            receipt_root=keccak(int_to_big_endian(random.randint(1000000,10000000)))
        ).get_signed(TESTNET_GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_incorrect_bloom():
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    invalid_block = valid_block.copy(
        header = valid_block.header.copy(
            bloom=213901
        ).get_signed(TESTNET_GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_incorrect_gas_used():
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    invalid_block = valid_block.copy(
        header = valid_block.header.copy(
            gas_used=213901
        ).get_signed(TESTNET_GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)


def test_import_invalid_block_incorrect_extra_data():
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    invalid_block = valid_block.copy(
        header = valid_block.header.copy(
            extra_data=33 * b'\x00'
        ).get_signed(TESTNET_GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)


def test_import_invalid_block_incorrect_reward_hash():
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    invalid_block = valid_block.copy(
        header = valid_block.header.copy(
            reward_hash=keccak(int_to_big_endian(random.randint(1000000,10000000)))
        ).get_signed(TESTNET_GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)


def test_import_valid_block_timestamp_a_little_bit_into_future():
    #
    # Make sure chronological chain matches canonical chain
    #
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    invalid_block = valid_block.copy(
        header = valid_block.header.copy(
            timestamp=int(time.time()+BLOCK_TIMESTAMP_FUTURE_ALLOWANCE)
        ).get_signed(TESTNET_GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    chain.import_block(invalid_block)

    chronological_window_timestamp = int(int(invalid_block.header.timestamp/TIME_BETWEEN_HEAD_HASH_SAVE)*TIME_BETWEEN_HEAD_HASH_SAVE)

    chronological_window = chain.chain_head_db.load_chronological_block_window(chronological_window_timestamp)

    print("Block hash {}".format(invalid_block.hash))
    print("Chronological window")
    print(chronological_window)

    # But check if that block is in the newest historical root hash

    historical_root_hashes = chain.chain_head_db.get_historical_root_hashes()
    print('historical root hashes:')
    print(historical_root_hashes)

    head_hash_from_saved_root_hash = chain.chain_head_db.get_chain_head_hash(invalid_block.header.chain_address)
    print("Chain head hash from saved root hash:")
    print(head_hash_from_saved_root_hash)

    chain.chain_head_db.root_hash = historical_root_hashes[-1][1]
    head_hash_from_newest_historical_root = chain.chain_head_db.get_chain_head_hash(invalid_block.header.chain_address)
    print("Chain head hash from newest historical root hash:")
    print(head_hash_from_newest_historical_root)

    ensure_chronological_chain_matches_canonical(chain)



#test_import_valid_block_timestamp_a_little_bit_into_future()

def test_import_invalid_block_timestamp_far_into_future():
    #
    # Make sure chronological chain matches canonical chain
    #
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    invalid_block = valid_block.copy(
        header = valid_block.header.copy(
            timestamp=int(time.time()+BLOCK_TIMESTAMP_FUTURE_ALLOWANCE*2)
        ).get_signed(TESTNET_GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

#test_import_invalid_block_timestamp_far_into_future()

def test_import_invalid_block_incorrect_chain_address():
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    invalid_block = valid_block.copy(
        header = valid_block.header.copy(
            chain_address=RECEIVER.public_key.to_canonical_address()
        ).get_signed(TESTNET_GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    with pytest.raises(ParentNotFound):
        chain.import_block(invalid_block)

def test_import_invalid_block_incorrect_signature():
    testdb1 = MemoryDB()

    TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    dummy_chain = TestnetChain(JournalDB(testdb1), TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    dummy_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    valid_block = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    invalid_block = valid_block.copy(
        header = valid_block.header.copy(
            v=100,
            r=100,
            s=100
        ))

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    with pytest.raises(Exception):
        chain.import_block(invalid_block)

def test_import_invalid_block_repeat_transaction():
    testdb1 = MemoryDB()

    chain = TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE, private_key = TESTNET_GENESIS_PRIVATE_KEY)

    transaction = chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    chain.import_current_queue_block()

    chain.add_transactions_to_queue_block(transaction)

    with pytest.raises(Exception):
        chain.import_current_queue_block()
    
    
def test_read_only_db():
    testdb1 = MemoryDB()
    
    chain = TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE, private_key = TESTNET_GENESIS_PRIVATE_KEY)
    
    testdb2 = MemoryDB(kv_store=testdb1.kv_store)
    
    chain.enable_read_only_db()
    
    transaction = chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    chain.import_current_queue_block()
    
    # Receive it
    
    chain_receiver = TestnetChain(chain.db, RECEIVER.public_key.to_canonical_address(), RECEIVER)
    chain_receiver.populate_queue_block_with_receive_tx()
    chain_receiver.import_current_queue_block()

    chain1 = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    chain2 = TestnetChain(testdb2, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    print(chain1.get_vm().state.account_db.get_receivable_transactions(RECEIVER.public_key.to_canonical_address()))
    print(chain2.get_vm().state.account_db.get_receivable_transactions(RECEIVER.public_key.to_canonical_address()))
    
# test_read_only_db()
# exit()

# test_import_invalid_block_repeat_transaction()
# exit()

def test_import_invalid_block_not_enough_gas():
    testdb1 = MemoryDB()

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    correct_nonce = chain.get_vm().state.account_db.get_nonce(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    transaction = chain.create_and_sign_transaction(
        nonce=correct_nonce,
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )


def test_get_block_hashes_that_are_new_for_this_historical_root_hash_timestamp():
    testdb = MemoryDB()

    create_blockchain_database_for_exceeding_tpc_cap(testdb, 5, 30)

    sender_chain = TestnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)
    # start_time = time.time()
    chronological_block_hash_timestamps_old_way = sender_chain.chain_head_db.load_chronological_block_window(int(int(time.time()/TIME_BETWEEN_HEAD_HASH_SAVE)*TIME_BETWEEN_HEAD_HASH_SAVE-TIME_BETWEEN_HEAD_HASH_SAVE*2))
    # print('old way took {}'.format(time.time() - start_time))

    # start_time = time.time()
    chronological_block_hash_timestamps_new_way = sender_chain.get_block_hashes_that_are_new_for_this_historical_root_hash_timestamp(int(int(time.time()/TIME_BETWEEN_HEAD_HASH_SAVE)*TIME_BETWEEN_HEAD_HASH_SAVE-TIME_BETWEEN_HEAD_HASH_SAVE))
    # print('new way took {}'.format(time.time() - start_time))

    # print(chronological_block_hash_timestamps_new_way)
    # print(chronological_block_hash_timestamps_old_way)

    assert chronological_block_hash_timestamps_old_way == chronological_block_hash_timestamps_new_way


# test_get_block_hashes_that_are_new_for_this_historical_root_hash_timestamp()
# sys.exit()


def get_block_hashes_that_are_new_for_this_historical_root_hash_timestamp():
    #testdb = LevelDB('/home/tommy/.local/share/helios/mainnet/chain/full')
    testdb = LevelDB('/WWW/.local/share/helios/mainnet/chain/full')
    #testdb = JournalDB(testdb)


    sender_chain = TestnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)
    start_time = time.time()
    chronological_block_hash_timestamps_old_way = sender_chain.chain_head_db.load_chronological_block_window(1554664000)
    print('old way took {}'.format(time.time() - start_time))

    start_time = time.time()
    chronological_block_hash_timestamps_new_way = sender_chain.get_block_hashes_that_are_new_for_this_historical_root_hash_timestamp(1554664000+TIME_BETWEEN_HEAD_HASH_SAVE)
    print('new way took {}'.format(time.time() - start_time))


    print(chronological_block_hash_timestamps_old_way)
    print(chronological_block_hash_timestamps_new_way)

    #assert chronological_block_hash_timestamps_old_way == chronological_block_hash_timestamps_new_way

    #exit()
    # sender_chain.try_to_rebuild_chronological_chain_from_historical_root_hashes(1554664000+TIME_BETWEEN_HEAD_HASH_SAVE)
    #
    # chronological_block_hash_timestamps_old_way = sender_chain.chain_head_db.load_chronological_block_window(1554664000)
    # print(chronological_block_hash_timestamps_old_way)

    #
    # for timestamp_hash in chronological_block_hash_timestamps_old_way:
    #     print(sender_chain.chaindb.exists(timestamp_hash[1]))
    #
    # print()
    #
    # for timestamp_hash in chronological_block_hash_timestamps_old_way:
    #     if not sender_chain.chaindb.is_in_canonical_chain(timestamp_hash[1]):
    #         header = sender_chain.chaindb.get_block_header_by_hash(timestamp_hash[1])
    #         print(encode_hex(header.chain_address))
    #         print(header.block_number)
    #
    # print()
    #
    # for timestamp_hash in chronological_block_hash_timestamps_old_way:
    #     print(sender_chain.chaindb.is_block_unprocessed(timestamp_hash[1]))


    assert chronological_block_hash_timestamps_old_way == chronological_block_hash_timestamps_new_way


# get_block_hashes_that_are_new_for_this_historical_root_hash_timestamp()
# sys.exit()


def test_chronological_block_initialization():
    '''
    This mimics a fast sync, which doesnt update chronological block windows, then we do an initialization and they should be the same.
    :return:
    '''
    testdb1 = MemoryDB()
    testdb2 = MemoryDB()

    tpc_of_blockchain_database = 1
    num_tpc_windows_to_go_back = 6*10 # 6 chronological block windows
    create_blockchain_database_for_exceeding_tpc_cap(testdb1,tpc_of_blockchain_database, num_tpc_windows_to_go_back, use_real_genesis=True)

    server = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    client = TestnetChain.from_genesis(testdb2, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE)

    server_chain_head_hashes = server.chain_head_db.get_head_block_hashes_list()
    for head_hash in server_chain_head_hashes:
        chain = server.get_all_blocks_on_chain_by_head_block_hash(head_hash)
        client.import_chain(block_list=chain,
                            save_block_head_hash_timestamp=False,
                            allow_replacement=True)


    # server_historical_root_hashes = server.chain_head_db.get_historical_root_hashes()
    # client_historical_root_hashes = client.chain_head_db.get_historical_root_hashes()
    #
    # print(server_historical_root_hashes)
    # print(client_historical_root_hashes)

    client.initialize_historical_root_hashes_and_chronological_blocks()

    server_historical_root_hashes = server.chain_head_db.get_historical_root_hashes()
    client_historical_root_hashes = client.chain_head_db.get_historical_root_hashes()

    assert(server_historical_root_hashes == client_historical_root_hashes)

    current_window = server.chain_head_db.current_window
    end = current_window - TIME_BETWEEN_HEAD_HASH_SAVE*10
    for current_timestamp in range(current_window, end, -TIME_BETWEEN_HEAD_HASH_SAVE):
        server_chronological_block_hashes = server.chain_head_db.load_chronological_block_window(current_timestamp)
        client_chronological_block_hashes = client.chain_head_db.load_chronological_block_window(current_timestamp)

        assert(server_chronological_block_hashes == client_chronological_block_hashes)


    test = client.chain_head_db.get_head_block_hashes_list()

# test_chronological_block_initialization()
# exit()

#debugging tool to find the first unprocessed block on all chains. Used to figure out why they didnt import when they should have
def get_first_unprocessed_blocks():
    from hvm.exceptions import HeaderNotFound, CanonicalHeadNotFound
    data = [('0x01034fe77ff8d466426ed8428b71c0bb0d35adeb', '0x05a25e2dd193ef746fb1cf8490fe534ccdf82dd21c31534ecec7a5ce0a45a265'), ('0x012de8fa687d568b4500a679f9f1c6033f79c287', '0x03d8ad31de1aa4597624116a11dca6d6b1d609717442484a2478353a8ca8cb6b'), ('0x038074ad75e0f0531e4586edf930a895b5b7da9b', '0x852f545813886a9e0ab8cfe0e5618683c62e5d8267f17547325005041594368c'), ('0x03bc338c12c52565fa8ed431e0f4cafb11e2be08', '0xb69c74ea4a103788ba7857bad7bc2ed674beab0431c79009f96429b5a7498f41'), ('0x09a6419fa9f8ae8ea4111d2738a7f4d2737a3439', '0x44750bd1037d52da742450fb5b21783b6657939b03ce1363a5be437e3583f994'), ('0x0b12b2d403020c96948d2ed3d715718971ff0eb9', '0x663bbf54f101f5032d1f3974cfb82c244c28a9a2b29c323c225823b19423d987'), ('0x0b7a497272dccc263aa7c535dcee7b973123b2f6', '0xea0d9a649e65cd47ad73aafc9d769d1f23aabbf232b920f8d3c9b18b06c3c0bc'), ('0x0c926a32cb87436fd167ec0f3ebca57b9e589d49', '0x2cb8eab0ded32c7ab222794ccb22a3106f40d8f73a1f41defc5085b4edde113a'), ('0x0d1630cb77c00d95f7fa32bccfe80043639681be', '0x8329d566e12e3e2f5920c70a89e4029026e5f5ed0efad58cebbf08d6a55700f2'), ('0x0d480b9eb65be0ef406a4a4ecbbe47206a55dc68', '0x36073b8c62bb4e3f82b010e67ea7e08efc65e746c5a2034cc9e50e27fd4d566f'), ('0x12f9c05b91c4fc611946eebf72a14a2234f631ef', '0x2b7561574c0c091906e1f7de1576edc248177d9e0c1dec8412587f276a417fa2'), ('0x1418f3692d4b31ac096b156f5ba4aa8abfa880ec', '0x7173ea2d229f01951c2b9c192cc385fb1eb30f9aaf21d30b908cb7e5b5351b90'), ('0x1432716bbd2d21a5bc36463398915856e18ea188', '0xccbb9f60c6e818b76af9b64e439a3768b23005d945ad03fe50842d6a1c8afdaa'), ('0x1479ced4bffb369c7d91cf30c57b88c6ce05f30b', '0xed0ebfa6f6cedb747e350818242c6695bc848ba24e82c2402cfc88d4ad7bba9b'), ('0x1699ae8389c71f52138cc48136d5968c60a0a455', '0x8471f21919383029d6eabda0da606fb194ba3e378dcde857f0038cb32147280d'), ('0x169fe82c72a6d3411cdbf75fc02f4ad3f04cdc9b', '0x47d3a7d64a6cef85b098ad45d69bb3eb1beefc166f185ca53379839851003e37'), ('0x1909a15ab3856d8a29dbb75e185a2c4886ebc6bc', '0xdb43ddd3eb6cb186756e215033142c3ac683bfc37376a426a92678c5908fae1e'), ('0x1d4a74debf0888b76230aafab4b085169d1e8de7', '0x66c1881cc9a87093df291b6afe527a20a202667df0e8e818f3324930fc03bf07'), ('0x1d9f5195ab4aae3144ba7e9c9685303aa101e07c', '0x984b4f16a4f7f91698d456cc9072d93f074fd7a8053a941ecda2147b54b8c7b8'), ('0x21858448dfa67d9e9152eb77682f00960df52500', '0x1c06e23c412ae601b4e1059ef54286f2acf14b9f6719b8555f4337b08c53a30f'), ('0x2247bb8575d718e88658e0312563829ba9d96e59', '0x5479e30060366fd18065280a71df46ea5be98631e4fb4b8b437e038a39334a0a'), ('0x263bd6276b4fbb2d375c6e057637b3ad04301a54', '0x99bd477d9b08243ee8a8785c5dee348d3f7c5593003a4d82f7144f0e4d759bf5'), ('0x2827161ab1abd67b84dab5092e3b8fa09f9acd71', '0x9e9fdf79014779a0e3ff3c44f4f230366252eb648cf3b6b62a417edc4c9a05a6'), ('0x2efb8285c5b84220c77e34ca39af40d93a99099b', '0x2f76efeddf5d12a36ea728b6b133247820d3d54cb75dae7c4088448dd8c0f870'), ('0x31972da202246ab9feabbf93eb880ade309ba55c', '0x43e47ed5904b575fd13d7f2a576cf11217e2fcbfd41e716750f245868513b645'), ('0x31d9ad687b81fbfa00ba861d2c998f061b5163a4', '0xf457e940b20715679beca8db0c5589fff08e5d1b5b74ad93763a899b874c198d'), ('0x35f2415225e6e907768313727b187b337d48ea1e', '0x148fd80322e37676daee168736e501f767f38ea1657d0eabfea81bcdd25d6197'), ('0x3ddc692527acefda1698d06ffa8655d440d487da', '0xa9e720d88a037cd4013ab4877243d6cd8036eddde0b6d0f44d77f1d4557ec4f8'), ('0x3e0b66f63e587cc120321d46d36ea837a80930ce', '0x8a0a491aafaa5661151c154c7d7118ab29e45e54e298b34dfcb9cabf50d16491'), ('0x3e8ae0e228ef036c18eb27c628d6a768d4a97669', '0x80b1538bd62632ddcabd677bf4c2c2d00c2a073f76d7bf71cf1696eb9366a6ef'), ('0x3ee89160f11743455ceea8826f357a701d9b363f', '0xa37e87cbc1c9714dd326928b6f1358dd2064e83f8b2d89c79a629f92823efe2c'), ('0x42ec6ed4c2f134d751d04a9bbfb65055e70890e9', '0xde350e4ee9600b05e16db06b40b2e0f74ff7d2e8cad310e46912ed60402713fb'), ('0x437537c22e4eff5d4b85b94aec0a96c85b43717b', '0x271054ba37b6ba008059c50f6636616b6fce3554da21e203d97fef224470b6a6'), ('0x487514d12b79a7033cf1b8e9bc42da80c5d57f2d', '0x4ea3074bcfd717ea3f6009bf8a5bf368fd1af8b28013ae51062ea85c2360a507'), ('0x4981f5f3bac29c6ff2ddf3a0266d189aadc3ccc4', '0xe3eadc6f0dfb2f26c8d2fdd4c3f62c1ab3b7b2d234d6bf2e212afb883171f3ed'), ('0x4b07a61249f8a967a6cea0203382d23ea03619cf', '0x2662d960638f1f0be0e0a790d2b3ec913b6514071f8391284cea5cb9046a3735'), ('0x4bed7d6a33e1ab35c70dfe38224fd6d5a5f61775', '0xfa0a0c2ba5705229e2c005ab0fd768a0568d575189424e68ef3e91abaca287a6'), ('0x4f256ff1beb6961db877e764e8163203a051ca2e', '0xe71fca9810d128f4d32f6e33dee2e7f5678c48ae8d83950bc8c267b1e99693e1'), ('0x52b3833a67e3dc4cd713591cf721e49282be22f7', '0xa4eb1e936b2707ea4441daa8e6b391359fe13f87a10018e24aa2f38f3f11ee0f'), ('0x5402ce340245277d84e2e39e11de973d92bb3b14', '0x93adcf9cc95bc2acb03a3b3a4a5bd91697a6553f8140208e52e418697aef0404'), ('0x5478ef229478f195ca5cbb8b1aa448370676c7da', '0x678e63e97a6b775d83cc81e8122ad6aeb210b287e1e3ecd13d9360343fe7e676'), ('0x54ff409cade6af780d15f2c3bf7d4d59827a6855', '0xd703c60a286853187e297b47f9216d58f5ba60e716713576efee699fa52d49c4'), ('0x55242b756d16419a7d76d04d1d24c43c02f4610f', '0x1d836828e32edf7a641f204767e3f207479ebbe2997afa3f136190bc34f09fe9'), ('0x595e786001754f3d436901e6cf8744216b773b5b', '0x5e417d3aafe1a722338a5fdf7a7ab59fb00ad452d8980f19dd56006ff09c0890'), ('0x5a74984378b57693e63f052380ed79fbec71d411', '0x586b3c71f8702f7699ebea77a979f960766f1b0e7e9e6a1bd33e55d7fb16ab6e'), ('0x60101e10ef5e87d3ee415030da4d207f2b0eea02', '0x148ac369d34656b95e94eb66198b4c2a8d667be845cf7a9c6b0624eb410694af'), ('0x62e65f7921f0614b72a25d6239227e55170139a7', '0xf8e9747eff379fcbaad602e0b23b7a408e14453405d069dbdc92eb8bf410fa65'), ('0x639025c0370a86909dd1b8dd249c2b271c6afeb7', '0x4e0e38772d997b53c91c99f6f6a9739a9b0d976c047acd742a95004e16db8c1c'), ('0x639b7eb1da6cbc18f6eef889c40d62f5ee33559c', '0x4cc147ca62068103450de0e52e4c0704758e18e86d76212f6374133c7c5b623b'), ('0x65f9e0af36e8d420e51942fcf9c0a9851699f86f', '0xd56f85e6ca01eebcb7e0fa1b0db972ec3e08608cf932c4e83c893cb927028ef1'), ('0x66c857cb622f3f84654f5d6b310c9bb25b1d7f29', '0xf325e015e15f44dfa4e0e720d116dfbeb7d1f8133709c33155867cbc5c22d981'), ('0x6e833d32a959d3760da35fcb67224b6a9dc445cc', '0xbcff3cfc10fc0b213a491cfb400ace8549f6c747d6bf8d78fae37064118bba6b'), ('0x6e895e602059c6655b6def4a62483940a1cb221a', '0x165b45ba0752ae802e9e27570273d4d412142f8563d405e3c6c43bcdfd732d0a'), ('0x72bdbd20bebf4c806650fd4027a78f5cf478457b', '0x67d63aaa4585cfcda8a9d34b4c7b07732cf88ec9b4957c3a7642ef7a28b9bfce'), ('0x79ec7668e388d6378483e3ef3dc840d0956dab5f', '0x23361221778c8fe043c90621f289c9d777b60ee07fbc159e27c2f9b2e9bdd9c9'), ('0x7cb6ff697d0f7ac22a3cb8056314f5f1a72cc15e', '0xc5ec47effc267ff22d10193a43cb01b6c62d7fcefc31b8b8963ca728da8072be'), ('0x7d74dee978a1f24a2e1efef9ba55534b29e9a7fb', '0xf51ef53c5b9c20cce009b70edd5ae515deeb414c96c7f4870f43188d9af058ed'), ('0x7e2e85530bd5f381b366c250f0772c8176e9cb34', '0xd49f5b360be8bbf023eb3086594139c28fff0be135701ece384e581857178f42'), ('0x81f5b662d7096609e391eac5cfebb9d4ac30bc9e', '0xea319a0f0359d418717656bda2e1dd75a96703a08e2492468f98cd9fa718bc38'), ('0x83f50e2d95d99996423a19eb122673bf286e39d9', '0x5fcd0c11605eee7816ed4ce527e3aafcf7d242b153dc6c805b97e2940b4d8b1e'), ('0x8bf592810856a13bc291ac245f03a0646af3d147', '0x7e52929f8a534f303f582cb93e6c6497ca4da91f0886e1627b31729fb12f231e'), ('0x8fa31a34d9760eadf6da573d57faabab38d76f55', '0x664fbadae56abf390eea0fb09d168230233f3dfb7f831a4a78b1f6e1a5aa33b2'), ('0x9032b55f3a06bd1215deff1f4c4b2922a0684331', '0x4f68ce090dac8b67d11dd1a6fa2098b314db4d11ff93a84735b470fe34b9fd06'), ('0x903b34ad7efd6f32607c9c42d4766017ea231e9b', '0xc69dbcd1da54a8ab6ebe7842b7ac2b4d6c7de34622d9ced2d701be5c955a76ed'), ('0x9064ad4fa186a89f713b895d97756eff8c4a1fb9', '0x6ecaa0fa461f9d6448b2ecbdc9a1ba0d3ae4a30a68f843c9ac2f074f5ca6cba2'), ('0x9160aac528a0b9308bcf300c32f47dc44ce029fd', '0x40c4eca224d666b0e085cc0876d918d09f2f3b7857d97000cc875bf875141735'), ('0x92b600bc408926cc306cfefdd3aad667f4d07458', '0xa7b4ad127e329cc0df39b62739b4ef0cd904e2c533e0942225a65b5ac1ddc541'), ('0x938fa3d9456ba5895f68adfee655acaf7666cafc', '0x367fd2a22e4751c6249397f1be550dbde96a0d53f0bbb3f68932cae4115e1f29'), ('0x958a04c208346a8e1dd9143f26efe34e543526b8', '0xc183cb8433b1f65b986b85a31bf43b7f58260aefa38fdd97a75e799f847a0d66'), ('0x97165ddaa0117b641c9757ebedd455b3e9249322', '0xd460718513a8186a9d60cd1869fd657e5d8f096683343a093ea2421e34fa9336'), ('0x997fa1522e22c6a52dbca9e7f6e2a18ad548f325', '0x2c2a3dd0fb44b8a0a5fbb6053dc366a875264dd57dab0e806150e888083f9c15'), ('0x9a72e836a6496e90a8d9342940c22faa58bb9a88', '0x718a5b26db5542858cc6e475e7a4fd774aa8b0717992b16ea914674c61e348f0'), ('0x9c8b20e830c0db83862892fc141808ea6a51fea2', '0x034c265e5a0f9fee45bc689f06917e9cd0cae7b4e4083caf04e8b84cfdea662f'), ('0x9e8320019148e31f444ad952fb2483ce4688eeb2', '0xc705d0c7db89636095bd85653dd72fcb0c138bb6c13b044c62066307c3ba1c1f'), ('0xa0d144e06f1d0bf5e7a88df2d86bfc34f7026911', '0xa56ea529bcc59c66ec0f7d8b2177834728a26a171a1fe69acd85d062cb7c89c8'), ('0xa2ab029ab7afd1b94b07481a080d88c356f21b03', '0x282d42a90c76476f0e4a85a5306e665cb18dfa5065fd335196c10e22387542e3'), ('0xa2fda2b600bfcde52a87600fddc7df8b0576eafd', '0x63bae90fe4cdb02778714dcec0dda7cadca30168b1d944146df15bb8a2f9d35e'), ('0xa5638eb7630aeefe5f4b549367698918f66e205e', '0xc92454437914f5ed87f60c50f588b4a3002e513d5074011420f01edf4afef1af'), ('0xa792b2dce3d4e63931a452edb914a8f363032229', '0x4008f7577ce67fe7f7276baeb7ffc1873f8468a0579cc1b4a4b8355e8ab5f554'), ('0xaca0ecdb5b44c86e1bb8f82a073d6fced2496da2', '0x39e9fa11a08e705867fb1ec589cd70bfb7458330d9331447b7066a11522264e7'), ('0xb2a520ad5773e834da5c4be3abe8ccf4671eaae7', '0x92d4057cccb5319f0cd695239d5396bcec010f438d0a131da0f799887a158ddd'), ('0xb4880f92b864b7f88af74f11b586535280273442', '0xc94ae9efaf7fa000ff20e024043803ee09d0cfbff71c155db084157e9fe716ad'), ('0xb5a167fa654c4ed4c22661a6a5730aeb33e5856d', '0xb9bff3001be7a11afa02d7aeeb55e4839ea9ebfb3369c7079c8b8a4a13937e6e'), ('0xb5ce21ed4eab528b536079ee0bb45587b7c369e4', '0x437fe7ee3f97f50408519fe1be2e4cff859e1927ec618b442e544813576b3aa6'), ('0xbb3f9d7d88231533a2373cfdfc2e574556aed597', '0x04275a5bceb55805f0cf42e25f42d1338c732974421c0a25d5d937981f36bcab'), ('0xc09e72144e55a7e0c15fbbd277981946c9d9a13e', '0x174dc28d52df74efe74a39444d8c8ca51dda7091ffa2717fa397b0b0526e0945'), ('0xc0f8f0d488444b90631dee00c61de647e5ccaca2', '0xe6c94c5b1e6cca443e163ab7a566759d84b46fa67f47b39d4445d8ad1e713bf7'), ('0xc12aa2a899a6b6d66d845238ba1cb21b2b475f24', '0x8cd428ad2c3d5f969feeb0657e0840e7e0e8cc427660d6b2177e822ce4b23785'), ('0xc26293c9c431d020f9443234c06ef1c7ef9de226', '0xec58da92d6a09daa42d22cd0e78d56ad7f839a73e603c92267e7239115dc9892'), ('0xc37ca2a57f5b8c08ccf13a9139f5757eec4d87d8', '0x05eff5210ceb656c855b4543c5d24965fd981deb30cd54783c6ba59196b13bd4'), ('0xc80ef715daa455a5071f722d60c3f1341244531a', '0xef00feeece6ad7c1735492b91af99305349fec30f339049b5a93d27c6eebf8b9'), ('0xc853895db7fa0e8209aa61fa67612c3e63dfd978', '0xfae77c874570b96eb7d5f5a2c1e2f7cd35b70060690ac42e07a24c7bad21f46f'), ('0xc97cd3180316c76f61957e7b7898f8a50d87f54d', '0x0ec3dabe5934d69e03681656bb699b177c4901d0a99e3b592ad7db2e76c7287f'), ('0xc9d9859fc3cda72b07d6f1c3bdbae29183c1b681', '0x40671c423b00e33ac5333ecff34cfa60fd0f1b9bafee6726518ab7647946df94'), ('0xcb5543d2e04aa46fe36a263d853ffc0635e6f245', '0x408ed2728673e148a322f2d790c27ba18cde8a2fddc0e886aa5baf426c5877b6'), ('0xcdb14527b67b3dd1a84d8e1111dc226915ea9d2f', '0x6927c6376a4452c9322bcffdf3321eeb120f7b52035001b511584c215f43e4df'), ('0xce37a69da0fde7158652c5a19b70b1cef8097cdf', '0x07bf7e75969e2474a8f42c84df5dc4f9704bba9db94d72ccc0129d92fe57e767'), ('0xce7e87d8cea288928364689ab18cbc8652b36858', '0xd59319e95d63ae8c5de35a60ee7266e5aeb895ed3a8a04e15b46ff44ecb076df'), ('0xd130fb34a53e456946eb9796117a13adc7048809', '0x1823c9e7fa65948553e9d5fc55a9a69ddf9c8f598bf39cf486e1fc4389cb179c'), ('0xd14b5c99078701937cd9c8bda6774358be31be4b', '0x76a9412d23d9eec889ecccf9793390959b8fb9b0221d9dc69c1646c2c9ef23f5'), ('0xd68f3ebecded46bcc8e14a901c237bc46642c806', '0x028f6f38fd3ae33fdfa8025ad67e3d8d7cb69d38c4af61aca772b48d9de18ddd'), ('0xd7277d33603fe910aaffb5793f1f0b7058bc019c', '0x075ada81efc10cf179fdf45ed708583ffb727a5052cc7ab84676c4ceb958dfa0'), ('0xd755185ac5cb1a04eb835c6c8d6c813e3b1b209c', '0xbb88286012177f074eebec595c2ae26ba7983ef4b0a0d4ef4e420c7953573213'), ('0xd76bebcab8b98306d1facc952ada5792eac47d50', '0xa7485b4ec366b5845eeea19e203f41aae9ec6a28970a78eefc3ad846784253d1'), ('0xd91edc2384491c5d16c939a011d28cec11d77851', '0x04976875753db21ea9548269db2a2655cf3cb441bd430470263b64c0f87cd9ac'), ('0xda6219f7c58354e3d86364cf3ff6e689a34a761f', '0x7363aca48d5b68301c88a2488689f5c1f6c601096a27f65452a067a54c9e0b2f'), ('0xda6c0852b56ca32850bb963c9c6015ca1989a1fa', '0xe8ac00b5465d6ac8ad3fa0d2242a3c26b9d38042c11063bd1d4c7b661de39b1b'), ('0xdb4ca426d53b59f60370274ffb19f2268dc33ddf', '0xb8cdbfc0295088a29417912cfbc76ef838cbc0d695d10eb789b6328151789e43'), ('0xdbac207ae9ec884a310bc8eac07e231e911d11be', '0xd2de7f20bc44131c14247dbdea6127f1d5389ec2efd8e9226a2d7587047c1d48'), ('0xdd77f9719d1eb5262d49d54079b9af25fb9f0e3a', '0x8f52aa7cfb2fe228508d1114fcbcf005ee0f19589b427aa14da626e87bd28230'), ('0xde3c6fa2b849c02faad90df69bd12e7e2b77293d', '0xe115e3ca8b27dadb5aac7413139415ba69078d9ff8f1bd182092386450216d83'), ('0xdf1604b6328e85320ef6ccad8e3d9727e12e1705', '0x684bf8a1f2e762361f2923cab9edabbaaec7098cdf2ddbf65ca7de810d914212'), ('0xdf2446a213e5402add0852da24561afb1469db28', '0x9b26db94ae6ebad967ceb9e27d2443196364fdf3b4139629e6a506597c77e27f'), ('0xe0596d1848fd3e538815a85f303c7452fa77c941', '0x5502da4934f6eb4acfb336f14062fc9ad54f09cedb34bcb21606e6a639f75ddb'), ('0xe3056ef068334a9d7cdb446a212cf7385287c044', '0xf7637ef8cc9b84b06610881ac9a3dd219250e74c60992c8cd3f966e964eb62fe'), ('0xe505161ad3e805fbd17cb34b672c350d0ac71439', '0x36f19e8feb647ce9043755e6ddfbe4085b750b645f1111dd02ea1be3aeaef97c'), ('0xe9869b87e505649a1fd6c538fa011c48c25685df', '0xd9466a8eb79f743cd86564cdcb45aaedd22154d00a2df74dd12b385a9b00b50c'), ('0xeb3af037b82bcab116c7c969f1c45dafc20dcaff', '0xaab9fa4305e5df72aad563633d70924ec4dbf0eccc453f424ec7ef592a8adf25'), ('0xf2e020f8fcd6bc4ae062838c73b8953ef2c30e8f', '0x8ef1e68eb1e27071f0f1fd340499e433cd95114220b6aab6a7edfdd4ee62e4b0'), ('0xf4878b72fd7c3c45b69fcfa87bfdb4d4c93b0b0b', '0x354c03befb714563ca4e2adddbad6ca2178ee17f2f435ed415ee6703c0c114a7'), ('0xf4f839f7e23b9457b49489222e3c885034c36cac', '0x399e65dc4591bbf2f55d2150b26b6924896e316e32d2644666799c2efd159f72'), ('0xf53b1e662e65bd8183575f0954e8dad2dee905b0', '0x9eed59651aeb1ec9ccb892e5888213c7b5ef5d58182c0cd561d3d837f782d258'), ('0xfb6842a8e743d8ba4f153b87e1b8def59b6bba0a', '0x4f028983e1299d8a401405691413868e640afce5ba94a42d07d9b681f0085625')]
    chain_addresses = [decode_hex(x[0]) for x in data]

    testdb1 = JournalDB(LevelDB('/home/tommy/.local/share/helios/mainnet/chain/full/'))

    chain = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    first_unprocessed_block_headers = []
    for chain_address in chain_addresses:
        try:
            first_unprocessed_block_number = chain.chaindb.get_canonical_head(chain_address).block_number+1
        except (HeaderNotFound, CanonicalHeadNotFound):
            first_unprocessed_block_number = 0

        try:
            first_unprocessed_block_headers.append(chain.chaindb.get_unprocessed_block_header_by_block_number(chain_address, first_unprocessed_block_number))
        except HeaderNotFound:
            pass

    print(first_unprocessed_block_headers)

    # we want to find out which one of these unprocessed blocks should have been processed. That is the case if
    # all of it's parents have been processed

    for header in first_unprocessed_block_headers:
        parent_block_hashes = []
        block = chain.get_block_by_header(header)

        unprocessed_parent_found = False
        parent_block_hashes.append(header.parent_hash)
        if chain.chaindb.is_block_unprocessed(header.parent_hash):
            unprocessed_parent_found = True

        for receive_transaction in block.receive_transactions:
            parent_block_hashes.append(receive_transaction.sender_block_hash)
            if chain.chaindb.is_block_unprocessed(receive_transaction.sender_block_hash):
                unprocessed_parent_found = True

        for node_staking_score in block.reward_bundle.reward_type_2.proof:
            parent_block_hashes.append(node_staking_score.head_hash_of_sender_chain)
            if chain.chaindb.is_block_unprocessed(node_staking_score.head_hash_of_sender_chain):
                unprocessed_parent_found = True

        if not unprocessed_parent_found:
            print("found")
            print(encode_hex(header.hash))
            print("all parents")
            print([encode_hex(x) for x in parent_block_hashes])

            # Lets check to make sure all parents are in the canonical chain
            if not chain.chaindb.is_in_canonical_chain(header.parent_hash):
                print("One not in canonical chain")

            for receive_transaction in block.receive_transactions:
                if not chain.chaindb.is_in_canonical_chain(receive_transaction.sender_block_hash):
                    print("One not in canonical chain")

            for node_staking_score in block.reward_bundle.reward_type_2.proof:
                if not chain.chaindb.is_in_canonical_chain(node_staking_score.head_hash_of_sender_chain):
                    print("One not in canonical chain")


        #is_in_canonical_chain(self, block_hash: Hash32)
    # if self.is_block_unprocessed(block.header.parent_hash):
    #     self.save_unprocessed_children_block_lookup(block.header.parent_hash)
    #
    # self.save_unprocessed_children_block_lookup_to_transaction_parents(block)
    # self.save_unprocessed_children_block_lookup_to_reward_proof_parents(block)

# get_first_unprocessed_blocks()
# exit()


def test_get_receivable_transactions_from_chronological_blocks():
    testdb1 = MemoryDB()

    chain = TestnetChain.from_genesis(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE, TESTNET_GENESIS_PRIVATE_KEY)

    receivable_1 = chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    receivable_2 = chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER2.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    receivable_3 = chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER2.public_key.to_canonical_address(),
        value=2,
        data=b"",
        v=0,
        r=0,
        s=0
    )


    chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=RECEIVER3.public_key.to_canonical_address(),
        value=100000000000000000,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    chain.import_current_queue_block()

    chain = TestnetChain(testdb1, RECEIVER3.public_key.to_canonical_address(), RECEIVER3)
    chain.populate_queue_block_with_receive_tx()
    chain.import_current_queue_block()

    min_time_between_blocks = chain.get_vm(timestamp=Timestamp(int(time.time()))).min_time_between_blocks
    print("waiting {} seconds before we can import the next block".format(min_time_between_blocks))
    time.sleep(min_time_between_blocks)

    receivable_4 = chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=21000,
        to=TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
        value=100,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    chain.import_current_queue_block()

    start_time = int(time.time() - TIME_BETWEEN_HEAD_HASH_SAVE*100)
    receivable_tx_hashes, addresses_with_receivable = chain.get_receivable_transaction_hashes_from_chronological(Timestamp(start_time))
    # print(receivable_tx_hashes)

    assert (receivable_1.hash in receivable_tx_hashes)
    assert (receivable_2.hash in receivable_tx_hashes)
    assert (receivable_3.hash in receivable_tx_hashes)
    assert (receivable_4.hash in receivable_tx_hashes)
    assert (len(receivable_tx_hashes) == 4)

    assert (TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address() in addresses_with_receivable)
    assert (RECEIVER.public_key.to_canonical_address() in addresses_with_receivable)
    assert (RECEIVER2.public_key.to_canonical_address() in addresses_with_receivable)
    assert (len(addresses_with_receivable) == 3)
    
    
    receivable_tx_hashes, addresses_with_receivable = chain.get_receivable_transaction_hashes_from_chronological(Timestamp(start_time), only_these_addresses=[RECEIVER2.public_key.to_canonical_address()])

    assert (receivable_2.hash in receivable_tx_hashes)
    assert (receivable_3.hash in receivable_tx_hashes)
    assert (len(receivable_tx_hashes) == 2)

    assert (RECEIVER2.public_key.to_canonical_address() in addresses_with_receivable)
    assert (len(addresses_with_receivable) == 1)

    with pytest.raises(ValidationError):
        chain.get_receivable_transaction_hashes_from_chronological(Timestamp(int(time.time()-TIME_BETWEEN_HEAD_HASH_SAVE*NUMBER_OF_HEAD_HASH_TO_SAVE)))
        
    receivable_tx_hashes, addresses_with_receivable = chain.get_receivable_transaction_hashes_from_chronological(Timestamp(int(time.time()) + 1))

    assert (len(receivable_tx_hashes) == 0)
    assert (len(addresses_with_receivable) == 0)

    

# test_get_receivable_transactions_from_chronological_blocks()
# exit()

# def make_trie_root_and_nodes( items):
#     return _make_trie_root_and_nodes(tuple(rlp.encode(item) for item in items))
#
#
# def _make_trie_root_and_nodes(items):
#     kv_store = {}  # type: Dict[bytes, bytes]
#     trie = HexaryTrie(kv_store, BLANK_ROOT_HASH, prune=True)
#     memory_trie = trie
#     for index, item in enumerate(items):
#         index_key = rlp.encode(index, sedes=rlp.sedes.big_endian_int)
#         print('ZZZZZZZZZZZZZ')
#         print(index)
#         print(index_key)
#         print(item)
#
#         memory_trie[index_key] = item
#     return trie.root_hash, kv_store
#
# def test_trie_root():
#     from secrets import token_bytes
#
#     list_of_bytes = []
#     for i in range(129):
#         #random_bytes = token_bytes(1)*999
#         random_bytes = ZERO_HASH32
#         list_of_bytes.append(random_bytes)
#
#     #print(list_of_bytes)
#     print(_make_trie_root_and_nodes(list_of_bytes))
#
# test_trie_root()
# exit()


def test_full_block():
    testdb = MemoryDB()

    chain = TestnetChain.from_genesis(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE, TESTNET_GENESIS_PRIVATE_KEY)

    for i in range(int(150)):
        print(i)
        chain.create_and_sign_transaction_for_queue_block(
            gas_price=1,
            gas=21000,
            to=RECEIVER.public_key.to_canonical_address(),
            value=1,
            data=b"",
            v=0,
            r=0,
            s=0
        )

    chain.import_current_queue_block()

    print("Importing max receive transactions now")
    chain = TestnetChain(testdb, RECEIVER.public_key.to_canonical_address(), RECEIVER)
    chain.populate_queue_block_with_receive_tx()
    chain.import_current_queue_block()


# test_full_block()

def test_over_full_block():
    testdb = MemoryDB()

    chain = TestnetChain.from_genesis(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PARAMS, TESTNET_GENESIS_STATE, TESTNET_GENESIS_PRIVATE_KEY)

    for i in range(int(151)):
        print(i)
        chain.create_and_sign_transaction_for_queue_block(
            gas_price=1,
            gas=21000,
            to=RECEIVER.public_key.to_canonical_address(),
            value=1,
            data=b"",
            v=0,
            r=0,
            s=0
        )
    with pytest.raises(Exception):
        chain.import_current_queue_block()


# test_over_full_block()

#
# def test_chronological_block_initialization_2():
#     '''
#     This mimics a fast sync, which doesnt update chronological block windows, then we do an initialization and they should be the same.
#     :return:
#     '''
#     # testdb1 = MemoryDB()
#     testdb1 = JournalDB(LevelDB('/home/tommy/.local/share/helios/mainnet/chain/full_bak/'))
#
#
#
#     server = TestnetChain(testdb1, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
#
#
#     server.initialize_historical_root_hashes_and_chronological_blocks()
#
#     server.initialize_historical_root_hashes_and_chronological_blocks()
#
#     server_historical_root_hashes = server.chain_head_db.get_historical_root_hashes()
#
#     test = server.chain_head_db.get_head_block_hashes_list()
#
# # test_chronological_block_initialization_2()
# # exit()



# Try importing a block with the same receive transaction twice.
# Try importing block with invalid parent hash
# Test importing reward bundles of different types
# test importing refund transactions
# test importing duplicate receive transactions
# try sending a transaction to self.
# try spending a receive transaction in same block.
# try importing a block with a receive transaction, but have the timestamp of that block earlier than the send block




#TODO: make test where block is imported that overwrites a different unprocessed block.