import logging
import os
import time
import sys
from pprint import pprint

import pytest

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

    COLLATION_SIZE, MIN_TIME_BETWEEN_BLOCKS)


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
from helios.dev_tools import create_dev_test_random_blockchain_database, add_transactions_to_blockchain_db, \
    create_dev_test_random_blockchain_db_with_reward_blocks
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
from hvm.vm.forks.helios_testnet.blocks import MicroBlock, HeliosTestnetBlock

from tests.integration_test_helpers import (
    ensure_blockchain_databases_identical,
    ensure_chronological_block_hashes_are_identical
)

def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(random_private_keys[instance_number])

SENDER = GENESIS_PRIVATE_KEY
RECEIVER = get_primary_node_private_helios_key(1)
RECEIVER2 = get_primary_node_private_helios_key(2)
RECEIVER3 = get_primary_node_private_helios_key(3)
RECEIVER4 = get_primary_node_private_helios_key(4)
RECEIVER5 = get_primary_node_private_helios_key(5)


def test_block_children_stake_calculation():
    if COIN_MATURE_TIME_FOR_STAKING <= 5:
        #    0-------------------------0    total stake should be receiver 1, 2, 3, 4 = 1+1+10000000000-21001-21000+0 = 9999979002
        #      \ \      \             /
        #       \ ---1   --3--       /
        #        ----2        \     /
        #                      ---4/

        testdb = MemoryDB()
        sender_chain = MainnetChain.from_genesis(testdb, SENDER.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)



        current_genesis_chain_head_number = sender_chain.chaindb.get_canonical_head(SENDER.public_key.to_canonical_address()).block_number

        assert(current_genesis_chain_head_number == 0)
        genesis_chain_next_head_block_number = sender_chain.header.block_number
        assert (genesis_chain_next_head_block_number == current_genesis_chain_head_number + 1)

        """
        Send 2 blocks
        """
        sender_chain = MainnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)
        sender_chain.create_and_sign_transaction_for_queue_block(
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

        sender_chain.import_current_queue_block()

        current_genesis_chain_head_number = sender_chain.chaindb.get_canonical_head(SENDER.public_key.to_canonical_address()).block_number
        assert (current_genesis_chain_head_number == 1)
        genesis_chain_next_head_block_number = sender_chain.header.block_number
        assert (genesis_chain_next_head_block_number == current_genesis_chain_head_number + 1)

        """
        Receive all tx in one block - genesis block must receive
        """
        receiver_chain = MainnetChain(testdb, RECEIVER.public_key.to_canonical_address(), RECEIVER)
        receiver_chain.populate_queue_block_with_receive_tx()
        receiver_chain.import_current_queue_block()

        receiver2_chain = MainnetChain(testdb, RECEIVER2.public_key.to_canonical_address(), RECEIVER2)
        receiver2_chain.populate_queue_block_with_receive_tx()
        receiver2_chain.import_current_queue_block()


        sender_chain = MainnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)
        sender_chain.create_and_sign_transaction_for_queue_block(
                    gas_price=0x01,
                    gas=0x0c3500,
                    to=RECEIVER3.public_key.to_canonical_address(),
                    value=10000000000,
                    data=b"",
                    v=0,
                    r=0,
                    s=0
                    )


        sender_chain.import_current_queue_block()

        current_genesis_chain_head_number = sender_chain.chaindb.get_canonical_head(SENDER.public_key.to_canonical_address()).block_number
        assert (current_genesis_chain_head_number == 2)
        genesis_chain_next_head_block_number = sender_chain.header.block_number
        assert (genesis_chain_next_head_block_number == current_genesis_chain_head_number + 1)


        receiver3_chain = MainnetChain(testdb, RECEIVER3.public_key.to_canonical_address(), RECEIVER3)
        receiver3_chain.populate_queue_block_with_receive_tx()
        receiver3_chain.import_current_queue_block()


        receiver3_chain = MainnetChain(testdb, RECEIVER3.public_key.to_canonical_address(), RECEIVER3)
        receiver3_chain.create_and_sign_transaction_for_queue_block(
                    gas_price=0x01,
                    gas=0x0c3500,
                    to=RECEIVER4.public_key.to_canonical_address(),
                    value=21001,
                    data=b"",
                    v=0,
                    r=0,
                    s=0
                    )


        receiver3_chain.import_current_queue_block()

        receiver4_chain = MainnetChain(testdb, RECEIVER4.public_key.to_canonical_address(), RECEIVER4)
        receiver4_chain.populate_queue_block_with_receive_tx()
        receiver4_chain.import_current_queue_block()

        receiver4_chain = MainnetChain(testdb, RECEIVER4.public_key.to_canonical_address(), RECEIVER4)
        receiver4_chain.create_and_sign_transaction_for_queue_block(
            gas_price=0x01,
            gas=21000,
            to=RECEIVER5.public_key.to_canonical_address(),
            value=1,
            data=b"",
            v=0,
            r=0,
            s=0
        )

        receiver4_chain.import_current_queue_block()

        time.sleep(COIN_MATURE_TIME_FOR_STAKING+1)

        print("getting balance of receiver2")
        # print(receiver2_chain.get_vm().state.account_db.get_balance(receiver2_chain.wallet_address))
        print("getting current stake")
        assert(receiver_chain.get_mature_stake() == 1), "{}".format(receiver_chain.get_mature_stake())
        assert(receiver2_chain.get_mature_stake() == 1), "{}".format(receiver2_chain.get_mature_stake())
        assert(receiver3_chain.get_mature_stake() == 10000000000-21001-21000), "{}".format(receiver3_chain.get_mature_stake())
        assert(receiver4_chain.get_mature_stake() == 0), "{}".format(receiver4_chain.get_mature_stake())

        #lets get the children stake of the genesis block
        genesis_block_hash = sender_chain.chaindb.get_canonical_block_hash(0, SENDER.public_key.to_canonical_address())
        assert(receiver4_chain.chaindb.get_block_stake_from_children(genesis_block_hash) == 9999958001), "{}".format(receiver_chain.chaindb.get_block_stake_from_children(genesis_block_hash))

        print("All stake maturity tests passed")
        print("All block children stake test passed")

# test_block_children_stake_calculation()
# sys.exit()





def test_send_transaction_then_receive():
    # testdb = LevelDB('/home/tommy/.local/share/helios/chain/full27')
    testdb = MemoryDB()
    sender_chain = MainnetChain.from_genesis(testdb, SENDER.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS,
                                             MAINNET_GENESIS_STATE)
    """
    Send 2 blocks
    """

    genesis_block_header = sender_chain.chaindb.get_canonical_block_header_by_number(0, SENDER.public_key.to_canonical_address())
    print('checking signature validity')
    print(genesis_block_header.is_signature_valid)

    sender_chain = MainnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)

    print('initial root_hash = ', sender_chain.chain_head_db.get_root_hash())
    print(sender_chain.chain_head_db.get_historical_root_hashes())
    # exit()

    vm = sender_chain.get_vm()
    print('initial balance = ', vm.state.account_db.get_balance(SENDER.public_key.to_canonical_address()))
    vm.state.account_db.delta_balance(SENDER.public_key.to_canonical_address(), 5)
    print('balance after delta= ', vm.state.account_db.get_balance(SENDER.public_key.to_canonical_address()))
    vm.state = vm.get_state_class()(
        db=vm.chaindb.db,
        execution_context=vm.block.header.create_execution_context(vm.previous_hashes)
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

    # print(sender_chain.chain_head_db.get_last_complete_historical_root_hash())
    # print(sender_chain.chain_head_db.get_historical_root_hashes())
    # print(sender_chain.chain_head_db.get_root_hash())
    ##exit()
    #    converted_block = sender_chain.get_vm().convert_block_to_correct_class(sender_block_1_imported)
    #    for i in range(len(sender_block_1_imported.transactions)):
    #        print(sender_block_1_imported.transactions[i]._meta.fields)
    #        print(converted_block.transactions[i]._meta.fields)
    #    #print(*list(dict(sender_block_1_imported._meta.fields).values()))
    #    exit()

    sender_chain = MainnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)
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
    receiver_chain = MainnetChain(testdb, RECEIVER.public_key.to_canonical_address(), RECEIVER)
    receiver_chain.populate_queue_block_with_receive_tx()
    block_0_imported = receiver_chain.import_current_queue_block()

    receiver2_chain = MainnetChain(testdb, RECEIVER2.public_key.to_canonical_address(), RECEIVER2)
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

    sender_chain = MainnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)
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

    receiver_chain = MainnetChain(testdb, RECEIVER.public_key.to_canonical_address(), RECEIVER)
    print('testtest3')
    historical_root_hashes = receiver_chain.chain_head_db.get_historical_root_hashes()
    print(receiver_chain.chain_head_db.root_hash)
    print(historical_root_hashes[-1][1])

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
    stake_from_children = receiver_chain.chaindb.get_block_stake_from_children(genesis_block_hash)
    sender_chain.chaindb.get_block_stake_from_children(genesis_block_hash)
    print("printing genesis block children stake")
    print(stake_from_children)

    print("trying to load root hash timestamps after given time")
    print(sender_chain.chain_head_db.get_historical_root_hashes(after_timestamp=time.time()))

    print(receiver_chain.chain_head_db.get_historical_root_hash(int(time.time()) + 1000))



# test_send_transaction_then_receive()
# sys.exit()

def import_chain(testdb1, testdb2):
    '''
    Node 2 with testdb2 imports chains from node 1 with testdb1
    :param testdb1:
    :param testdb2:
    :return:
    '''
    node_1 = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    next_head_hashes = node_1.chain_head_db.get_next_n_head_block_hashes(ZERO_HASH32, 0, 99999)
    print("IMPORTING {} CHAINS".format(len(next_head_hashes)))


    for next_head_hash in next_head_hashes:
        chain_address = node_1.chaindb.get_chain_wallet_address_for_block_hash(next_head_hash)

        chain_to_import = node_1.get_all_blocks_on_chain(chain_address)

        node_2 = MainnetChain(testdb2, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)
        node_2.import_chain(block_list=chain_to_import)


    ensure_blockchain_databases_identical(testdb1, testdb2)
    ensure_chronological_block_hashes_are_identical(testdb1, testdb2)

def _test_import_unprocessed_blocks(base_db = None):

    testdb1 = create_dev_test_random_blockchain_db_with_reward_blocks(base_db = base_db, num_iterations=30)
    testdb2 = MemoryDB()

    node_1 = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)
    node_2 = MainnetChain.from_genesis(testdb2, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                                       MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

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
    MainnetChain.from_genesis(testdb2, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

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


def import_chronological_block_window(testdb1, testdb2):

    node_1 = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)
    node_2 = MainnetChain(testdb2, RECEIVER.public_key.to_canonical_address(), RECEIVER)

    node_1_historical_root_hashes = node_1.chain_head_db.get_historical_root_hashes()

    for timestamp_root_hash in node_1_historical_root_hashes:
        print("Importing chronological block window for timestamp {}".format(timestamp_root_hash[0]))
        # timestamp of chronological that we are importing: node_1_historical_root_hashes[-2][0]
        chronological_blocks = node_1.get_all_chronological_blocks_for_window(timestamp_root_hash[0])

        # make sure propogate_block_head_hash_timestamp_to_present = True and False works
        node_2.import_chronological_block_window(chronological_blocks, timestamp_root_hash[0])

    ensure_blockchain_databases_identical(testdb1, testdb2)
    ensure_chronological_block_hashes_are_identical(testdb1, testdb2)


def test_import_chronolgical_block_windows():
    # Where node 2 has no blocks other than genesis block on genesis chain
    testdb1 = MemoryDB()
    testdb2 = MemoryDB()

    create_dev_test_random_blockchain_database(testdb1)
    MainnetChain.from_genesis(testdb2, RECEIVER.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

    import_chronological_block_window(testdb1, testdb2)

    # Where node 2 has a different blockchain database. This requires overwriting.
    testdb1 = MemoryDB()
    testdb2 = MemoryDB()

    create_dev_test_random_blockchain_database(testdb1)
    create_dev_test_random_blockchain_database(testdb2)

    import_chronological_block_window(testdb1, testdb2)

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
    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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

    MainnetChain.from_genesis(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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
            block_number=2).get_signed(GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    print('Second nonce =', block_with_same_nonse_transaction.transactions[0].nonce)
    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)
    chain.import_block(valid_block)
    with pytest.raises(ValidationError):
        chain.import_block(block_with_same_nonse_transaction)

def test_import_invalid_transaction_nonce_too_great():
    testdb1 = MemoryDB()

    MainnetChain.from_genesis(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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

    invalid_block = dummy_chain.import_current_queue_block()

    # need to give it the correct parent hash
    invalid_block = invalid_block.copy(
        header = invalid_block.header.copy(
            parent_hash=valid_block.header.parent_hash,
            block_number=1).get_signed(GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    print('Second nonce =', invalid_block.transactions[0].nonce)

    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)


def test_import_invalid_block_wrong_parent_hash():
    testdb1 = MemoryDB()

    MainnetChain.from_genesis(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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
            block_number=1).get_signed(GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)
    chain.import_block(valid_block)
    with pytest.raises(ValidationError):
        chain.import_block(block_with_same_nonse_transaction)


def test_import_invalid_block_gas_limit_too_small():
    testdb1 = MemoryDB()

    MainnetChain.from_genesis(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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
        ).get_signed(GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_gas_limit_too_large():
    testdb1 = MemoryDB()

    MainnetChain.from_genesis(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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
        ).get_signed(GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_incorrect_account_hash():
    testdb1 = MemoryDB()

    MainnetChain.from_genesis(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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
        ).get_signed(GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_incorrect_account_balance():
    testdb1 = MemoryDB()

    MainnetChain.from_genesis(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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
        ).get_signed(GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_incorrect_transaction_root():
    testdb1 = MemoryDB()

    MainnetChain.from_genesis(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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
        ).get_signed(GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_incorrect_receive_transaction_root():
    testdb1 = MemoryDB()

    MainnetChain.from_genesis(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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
        ).get_signed(GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_incorrect_receipt_root():
    testdb1 = MemoryDB()

    MainnetChain.from_genesis(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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
        ).get_signed(GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_incorrect_bloom():
    testdb1 = MemoryDB()

    MainnetChain.from_genesis(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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
        ).get_signed(GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_incorrect_gas_used():
    testdb1 = MemoryDB()

    MainnetChain.from_genesis(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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
        ).get_signed(GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)


def test_import_invalid_block_incorrect_extra_data():
    testdb1 = MemoryDB()

    MainnetChain.from_genesis(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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
        ).get_signed(GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)


def test_import_invalid_block_incorrect_reward_hash():
    testdb1 = MemoryDB()

    MainnetChain.from_genesis(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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
        ).get_signed(GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_incorrect_chain_address():
    testdb1 = MemoryDB()

    MainnetChain.from_genesis(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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
        ).get_signed(GENESIS_PRIVATE_KEY, dummy_chain.network_id))

    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    with pytest.raises(ValidationError):
        chain.import_block(invalid_block)

def test_import_invalid_block_incorrect_signature():
    testdb1 = MemoryDB()

    MainnetChain.from_genesis(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

    dummy_chain = MainnetChain(JournalDB(testdb1), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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

    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    with pytest.raises(Exception):
        chain.import_block(invalid_block)


def test_import_invalid_block_not_enough_gas():
    testdb1 = MemoryDB()

    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    correct_nonce = chain.get_vm().state.account_db.get_nonce(GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

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

# Try importing a block with the same receive transaction twice.
# Try importing block with invalid parent hash
# Test importing reward bundles of different types
# test importing refund transactions
# test importing duplicate receive transactions
# try sending a transaction to self.
# try spending a receive transaction in same block.
# try importing a transaction with negative gas price or 0 gas price.





#TODO: make test where block is imported that overwrites a different unprocessed block.