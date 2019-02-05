import logging
import os
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

from helios_logging import (
    setup_helios_logging,
    with_queued_logging,
)

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

from keyBox import keyBox
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

#for testing purposes we will just have the primary private key hardcoded
#TODO: save to encrypted json file
#primary_private_keys = [b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5', b'\xa41\x95@\xbb\xa5\xde\xbbc\xffR\x8a\x18\x06\x95\xa3\xd7\xd2\x95]5{\x12\xe4n\xb6R\xd7S\x96\xf0+', b'\xd8>Fh\xefT\x04jf\x13\xca|E\xc4\x91\xed\x07\xcd\x02fW\xd8s;\xd8\xe4\xde\xb9\xbc\xe4\xf0I', b'\x83\x1d\xf6\xaf-\x00\xbfS4\x0f\xcds\x18"\xdd\x906]e\xfc\xe6\x0c?\xb1v20\xced7y\xf4', b")M\xf4\x1c\xb7\xe0Z\xf4\x17F\x9b\x089'\x004\xd3\x89\xd8\x80\xf5`\xa2\x11\x00\x90\xbd\x0f&KjZ", b'RI\xda\xbc7\xc4\xe8\tz\xfaI\x1f\xa1\x02{v\x0e\xac\x87W\xa2s\x81L4M\xad\xbd\xb3\x84\xaae', b'>kG\xd5\xb3qG\x84\xa6"\x1c~\xb6\xbf\x96\xac\n\x88\xfb\x05\x8aG\r\xe9Z\x16\x15\xb1P\xe0\xb7[', b'\x87\xf6\xb1\xa7v\x8bv<\xa3\xe5\xb18\xa7u\x99\xbaBa\xe9\xd5\x0e\xcb\x0f?\x84nZ\xba\xdf\xa3\x8a~', b'`$g\xe9\xa5r\xd2\xacG&\xf81^\x98\xf7\xda\xa5\xf4\x93)\xf3\x0c\x18\x84\xe4)!\x9dR\xa0\xac\xd3', b'\xcfd\xd5|\xe2\xf1\xda\xb9\x1f|\xb9\xdc\xeb \xd7\xb0\x81g\xdc\x03\xd6dQ\xf14\x19`\x94o\xf7\xc7\x1b', b'}LO\x14($d\n!\x1a\x91\xa8S\xb3\x05\xaa\x89\xf2\x0b\x97\xd3\x1c#\xe7\x86g`\xf1\x1a\xedXW']
from hvm.constants import random_private_keys
from hvm.vm.forks.helios_testnet.blocks import MicroBlock, HeliosTestnetBlock

primary_private_keys = random_private_keys
def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(primary_private_keys[instance_number])

SENDER = GENESIS_PRIVATE_KEY
RECEIVER = get_primary_node_private_helios_key(1)
RECEIVER2 = get_primary_node_private_helios_key(2)
RECEIVER3 = get_primary_node_private_helios_key(3)
RECEIVER4 = get_primary_node_private_helios_key(4)

HELIOS_HEADER = (
    "\n"    
    " __  __     ______     __         __     ______     ______    \n"
    "/\ \_\ \   /\  ___\   /\ \       /\ \   /\  __ \   /\  ___\   \n"
    "\ \  __ \  \ \  __\   \ \ \____  \ \ \  \ \ \/\ \  \ \___  \  \n"
    " \ \_\ \_\  \ \_____\  \ \_____\  \ \_\  \ \_____\  \/\_____\ \n"
    "  \/_/\/_/   \/_____/   \/_____/   \/_/   \/_____/   \/_____/ \n"
)                                                       

from hvm.constants import GENESIS_PARENT_HASH
from eth_utils import is_hex_address

log_level = getattr(logging, 'DEBUG')
#log_level = getattr(logging, 'INFO')
logger, log_queue, listener = setup_helios_logging(log_level)
logger.propagate = False
#logger.info(HELIOS_HEADER)


"""
Initialize chain from genesis params
"""
#print('creating mainnetchain from genesis state')
#chain = MainnetChain.from_genesis(testdb, SENDER.public_key.to_canonical_address(), RECEIVER, MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

def test_transaction_creation_time():
    #testdb = LevelDB('/home/tommy/.local/share/helios/chain/full28')
    testdb = MemoryDB()
    start = time.time()
    sender_chain = MainnetChain.from_genesis(testdb, SENDER.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)
    
    sender_chain = MainnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)    
    for i in range(100):
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
    
    print("creation duration = {}".format(time.time()-start))
    start = time.time()
    sender_chain.import_current_queue_block()
    print("saving duration = {}".format(time.time()-start))

#import cProfile
#pr = cProfile.Profile()
#pr.enable()
##cProfile.run(test_transaction_creation_time())
#test_transaction_creation_time()
#pr.disable()
#
#pr.print_stats(.1, 'foo:')
#exit()

def test_block_children_stake_calculation():
    
    
#    0-------------------------0    total stake should be receiver 1, 2, 3, 4 = 1+1+10000000000-21000-1+1 = 9999979002
#      \ \      \             /
#       \ ---1   --3--       /
#        ----2        \     /
#                      ---4/
        
    testdb = MemoryDB()
    sender_chain = MainnetChain.from_genesis(testdb, SENDER.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)
    
    #sender_chain.chain_head_db.test()
    #exit()
    
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
    
    receiver3_chain = MainnetChain(testdb, RECEIVER3.public_key.to_canonical_address(), RECEIVER3)
    receiver3_chain.populate_queue_block_with_receive_tx()
    receiver3_chain.import_current_queue_block()
    
    
    receiver3_chain = MainnetChain(testdb, RECEIVER3.public_key.to_canonical_address(), RECEIVER3)  
    receiver3_chain.create_and_sign_transaction_for_queue_block(
                gas_price=0x01,
                gas=0x0c3500,
                to=RECEIVER4.public_key.to_canonical_address(),
                value=1,
                data=b"",
                v=0,
                r=0,
                s=0
                )
    

    receiver3_chain.import_current_queue_block()
    
    receiver4_chain = MainnetChain(testdb, RECEIVER4.public_key.to_canonical_address(), RECEIVER4)
    receiver4_chain.populate_queue_block_with_receive_tx()
    receiver4_chain.import_current_queue_block()
    
    time.sleep(COIN_MATURE_TIME_FOR_STAKING+1)
    
    print("getting balance of receiver2")
    print(receiver2_chain.get_vm().state.account_db.get_balance(receiver2_chain.wallet_address))
    print("getting current stake")
    assert(receiver_chain.get_mature_stake() == 1), "{}".format(receiver_chain.get_mature_stake())
    assert(receiver2_chain.get_mature_stake() == 1), "{}".format(receiver2_chain.get_mature_stake())
    assert(receiver3_chain.get_mature_stake() == 9999978999), "{}".format(receiver3_chain.get_mature_stake())
    assert(receiver4_chain.get_mature_stake() == 1), "{}".format(receiver4_chain.get_mature_stake())

    #lets get the children stake of the genesis block
    genesis_block_hash = sender_chain.chaindb.get_canonical_block_hash(0)
    assert(receiver_chain.get_block_stake_from_children(genesis_block_hash) == 9999979002), "{}".format(receiver_chain.get_block_stake_from_children(genesis_block_hash))

    print("All stake maturity tests passed")
    print("All block children stake test passed")
    exit("Successful test finished")

# test_block_children_stake_calculation()
# exit()
    
def test_send_transaction_then_receive():
    #testdb = LevelDB('/home/tommy/.local/share/helios/chain/full27')
    testdb = MemoryDB()
    sender_chain = MainnetChain.from_genesis(testdb, SENDER.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)
    """
    Send 2 blocks
    """


    genesis_block_header = sender_chain.chaindb.get_canonical_block_header_by_number(0)
    print('checking signature validity')
    print(genesis_block_header.is_signature_valid)

    
    sender_chain = MainnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)    
    
    print('initial root_hash = ',sender_chain.chain_head_db.get_root_hash())
    print(sender_chain.chain_head_db.get_historical_root_hashes())
    #exit()
    
    vm = sender_chain.get_vm()
    print('initial balance = ', vm.state.account_db.get_balance(SENDER.public_key.to_canonical_address()))
    vm.state.account_db.delta_balance(SENDER.public_key.to_canonical_address(), 5)
    print('balance after delta= ', vm.state.account_db.get_balance(SENDER.public_key.to_canonical_address()))
    vm.state = vm.get_state_class()(
                db=vm.chaindb.db, 
                execution_context=vm.block.header.create_execution_context(vm.previous_hashes)
                )
    print('balance after state refresh = ', vm.state.account_db.get_balance(SENDER.public_key.to_canonical_address()))
    #exit()


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
    #print('initial root_hash = ',sender_chain.chain_head_db.get_root_hash())
    #print(sender_chain.chain_head_db.get_historical_root_hashes())
    balance_1 = sender_chain.get_vm().state.account_db.get_balance(SENDER.public_key.to_canonical_address())
    print('BALANCE BEFORE SENDING TX = ', balance_1)
    sender_block_1_imported = sender_chain.import_current_queue_block()
    balance_2 = sender_chain.get_vm().state.account_db.get_balance(SENDER.public_key.to_canonical_address())
    print('BALANCE AFTER SENDING TX = ', balance_2)
    assert((balance_1 - balance_2) == (tx.intrinsic_gas*2+2))
    print("Passed gas and balance test")


    #print(sender_chain.chain_head_db.get_last_complete_historical_root_hash())
    #print(sender_chain.chain_head_db.get_historical_root_hashes())
    #print(sender_chain.chain_head_db.get_root_hash())
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

    #there should be 3 chians now. Lets make sure there are 3 saved head hashes in the chain_head_db database
    chain_head_root_hash = receiver_chain.chain_head_db.get_latest_historical_root_hash()[1]
    block_hashes = receiver_chain.chain_head_db.get_head_block_hashes_list(chain_head_root_hash)
    assert(len(block_hashes) == 3)
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
    
#    head_hash = receiver_chain.chaindb.get_canonical_head_hash(wallet_address = RECEIVER.public_key.to_canonical_address())
#    print('middle {}'.format(head_hash))
#    
#    #####
#    receiver_chain.discard_journal(journal_record)
#    receiver_chain.disable_journal_db()
#        
#    head_hash = receiver_chain.chaindb.get_canonical_head_hash(wallet_address = RECEIVER.public_key.to_canonical_address())
#    print('after {}'.format(head_hash))
#    exit()
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

    send_transaction = sender_block.transactions[0]
    receive_transaction = sender_block.receive_transactions[0]




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

    print("checking that block account_balance matches account_db. Expected = {}".format(block_2_imported.header.account_balance))
    assert(block_2_imported.header.account_balance == receiver_chain.get_vm().state.account_db.get_balance(RECEIVER.public_key.to_canonical_address()))

    print("Checking that imported blocks are the same as blocks retreived from DB")
    block_0_from_db = receiver_chain.chaindb.get_block_by_number(0, receiver_chain.get_vm().get_block_class())
    block_1_from_db = receiver_chain.chaindb.get_block_by_number(1, receiver_chain.get_vm().get_block_class())
    block_2_from_db = receiver_chain.chaindb.get_block_by_number(2, receiver_chain.get_vm().get_block_class())
    sender_block_1_from_db = receiver_chain.chaindb.get_block_by_number(1, receiver_chain.get_vm().get_block_class(), SENDER.public_key.to_canonical_address())
    
    assert(block_0_imported.header.account_hash == block_0_from_db.header.account_hash)
    
    assert(block_0_imported == block_0_from_db)
    assert(block_1_imported == block_1_from_db)
    assert(block_2_imported == block_2_from_db)
    assert(sender_block_1_imported == sender_block_1_from_db)

    print("Passed test")
    
    print("printing entire receiver chain")
    all_blocks = receiver_chain.chaindb.get_all_blocks_on_chain(receiver_chain.get_vm().get_block_class())
    print(all_blocks)
    
    print("printing head hashes")
    print(list(receiver_chain.chain_head_db.get_head_block_hashes()))
    #exit()
    
    """
    check that account hash in the database matches that on the canonical head
    """
    account_hash = sender_chain.get_vm().state.account_db.get_account_hash(sender_chain.wallet_address)
    print('account_hash in database', account_hash)
    account_hash_on_block = sender_chain.get_canonical_head().account_hash
    print("account_hash on canonical head", account_hash_on_block)
    
    """
    check that the head hashes are correctly saved:
    """
    sender_head = sender_chain.get_canonical_head()
    print("sender head hash = {}".format(sender_head.hash))
    print("sender head hash from chain head hash trie = {}".format(receiver_chain.chain_head_db.get_chain_head_hash(sender_chain.wallet_address)))
    
    receiver_head = receiver_chain.get_canonical_head()
    print("receiver head hash = {}".format(receiver_head.hash))
    print("receiver head hash from chain head hash trie = {}".format(receiver_chain.chain_head_db.get_chain_head_hash(receiver_chain.wallet_address)))
    
    #now lets load the historical head hashes
    historical_root_hashes = receiver_chain.chain_head_db.get_historical_root_hashes()
    hist_root_hash_int = [[x[0], x[1]] for x in historical_root_hashes]
    print(hist_root_hash_int)
    #test to make sure they are in order and have the correct spacing
    for i in range(1, len(hist_root_hash_int)):
        if hist_root_hash_int[i-1][0] != hist_root_hash_int[i][0]-TIME_BETWEEN_HEAD_HASH_SAVE:
            print("fail")
    
    print('testtest4')
    print(receiver_chain.chain_head_db.root_hash)
    print(historical_root_hashes[-1][1])
    assert(receiver_chain.chain_head_db.root_hash == historical_root_hashes[-1][1])
    
    #try retreiving a block at a timestamp
    #block_hash_at_timestamp = receiver_chain.chain_head_db.get_chain_head_hash_at_timestamp(sender_chain.wallet_address, 1509021000)
    #print(block_hash_at_timestamp)
    #print('printing chronological blocks')
    #chronological_blocks = receiver_chain.chain_head_db.load_chronological_block_window(1529096000)
    #print([[x[0]] for x in chronological_blocks])
    #print(chronological_blocks)
    print("getting current stake")
    current_stake = receiver_chain.get_mature_stake()
    print(current_stake)
    
    #lets get the children stake of the genesis block
    genesis_block_hash = sender_chain.chaindb.get_canonical_block_hash(0)
    print("genesis block hash", genesis_block_hash)
    stake_from_children = receiver_chain.get_block_stake_from_children(genesis_block_hash)
    sender_chain.get_block_stake_from_children(genesis_block_hash)
    print("printing genesis block children stake")
    print(stake_from_children)
    
    print("trying to load root hash timestamps after given time")
    print(sender_chain.chain_head_db.get_historical_root_hashes(after_timestamp = time.time()))
    
    print(receiver_chain.chain_head_db.get_historical_root_hash(int(time.time())+1000))
    
test_send_transaction_then_receive()
exit()


def test_import_chain():
    #testdb = LevelDB('/home/tommy/.local/share/helios/chain/full27')
    #testdb1 = LevelDB('/home/tommy/.local/share/helios/chain/fuck_1')
    testdb1 = MemoryDB()
    testdb2 = MemoryDB()
    
    from helios.dev_tools import create_dev_test_random_blockchain_database
    
    create_dev_test_random_blockchain_database(testdb1)
    
    node_1 = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)
    
    print("genesis chain length")
    print(node_1.chaindb.get_canonical_head(wallet_address = b"\xdbL\xa4&\xd5;Y\xf6\x03p'O\xfb\x19\xf2&\x8d\xc3=\xdf").block_number)
    exit()
    
    root_hashes = node_1.chain_head_db.get_historical_root_hashes()
    print(root_hashes)
    
    next_head_hashes = node_1.chain_head_db.get_next_n_head_block_hashes(ZERO_HASH32, 0, 99999)
    print("IMPORTING {} CHAINS".format(len(next_head_hashes)))
    
    node_2 = MainnetChain.from_genesis(testdb2, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY, MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)
    print(encode_hex(GENESIS_PRIVATE_KEY.public_key.to_canonical_address()))
    print(node_2.get_vm().state.account_db.get_balance(GENESIS_PRIVATE_KEY.public_key.to_canonical_address()))
    i = 0
    wallet_addresses = []
    for next_head_hash in next_head_hashes:
        chain_address = node_1.chaindb.get_chain_wallet_address_for_block_hash(next_head_hash)
        #print(chain_address)    
        wallet_addresses.append(chain_address)
        
        chain_to_import = node_1.chaindb.get_all_blocks_on_chain(node_1.get_vm().get_block_class(), chain_address)
        #print(chain_to_import)

#        for block in chain_to_import:
#            print("printing block transactions")
#            if encode_hex(block.hash) == '0xa560ef23905a557ca3e6da5b28d5cdfe16a78af4baa61a3810ce88697ee3c37d':
#                print('printing transactions')
#                print([encode_hex(x.to) for x in block.transactions])
#                print('printing receive transactions')
#                print([encode_hex(x.to) for x in block.receive_transactions])
  
        
        node_2 = MainnetChain(testdb2, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)
        print("IMPORTING CHAIN number {}".format(i))
        node_2.import_chain(block_list = chain_to_import)
        i+=1
    
    #print("finished importing chain. now printing the number of chains")
    next_head_hashes_node_2 = node_2.chain_head_db.get_next_n_head_block_hashes(ZERO_HASH32, 0, 99999)
    assert(next_head_hashes == next_head_hashes_node_2)
    print("passed chain head hash check")
    
    for wallet_address in wallet_addresses:
        balance_at_node_1 = node_1.get_vm().state.account_db.get_balance(wallet_address)
        balance_at_node_2 = node_2.get_vm().state.account_db.get_balance(wallet_address)
        assert(balance_at_node_1 == balance_at_node_2 )
        print(balance_at_node_1)
    print("passed account balance check")
 
# test_import_chain()
# exit()
       
def test_import_chain_overwrite_existing():
    #testdb1 = LevelDB('/home/tommy/.local/share/helios/chain/fuck_279')
    #testdb2 = LevelDB('/home/tommy/.local/share/helios/chain/fuck_280')
    testdb1 = MemoryDB()
    testdb2 = MemoryDB()
    #testdb1 = JournalDB(LevelDB('/home/tommy/.local/share/helios/chain/fuck_245'))
    #testdb2 = JournalDB(LevelDB('/home/tommy/.local/share/helios/chain/fuck_255'))
    #testdb1 = LevelDB('/home/tommy/.local/share/helios/chain/fuck_26')
    #testdb2 = LevelDB('/home/tommy/.local/share/helios/chain/fuck_27')
    
    from helios.dev_tools import create_dev_test_random_blockchain_database
    
    create_dev_test_random_blockchain_database(testdb1)
    create_dev_test_random_blockchain_database(testdb2)
    
    #exit()
    #order of chains
#    ['0xdb4ca426d53b59f60370274ffb19f2268dc33ddf', 
#     '0x885ab3a6cf9f3ccd71a834d5be2eabd08b089e00', 
#     '0xf76eac4faae31632570b886fb27cdf7c9da368ef', 
#     '0x094c08ca4a316c1ec9326ae29872340dcf0028ac', 
#     '0xfc89e5ba946cc4279edf2b090b5e9258c3a11fbb']
    
    testdb1 = JournalDB(testdb1)
    testdb2 = JournalDB(testdb2)
            
    node_1 = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)
    
#    print(node_1.chain_head_db.get_historical_root_hashes())
#    exit()
    
    next_head_hashes = node_1.chain_head_db.get_next_n_head_block_hashes(ZERO_HASH32, 0, 99999)
    #print("IMPORTING {} CHAINS".format(len(next_head_hashes)))
    
    
    i = 0
    wallet_addresses = []
    
    
    for next_head_hash in next_head_hashes:
        chain_address = node_1.chaindb.get_chain_wallet_address_for_block_hash(next_head_hash)

        wallet_addresses.append(chain_address)
        
        chain_to_import = node_1.chaindb.get_all_blocks_on_chain(node_1.get_vm().get_block_class(), chain_address)

        node_2 = MainnetChain(testdb2, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)
        #print("IMPORTING CHAIN number {}".format(i))
        node_2.import_chain(block_list = chain_to_import)
        i+=1
        
    #####
    #Now we test to make sure both nodes are identical
    #####
    node_2 = MainnetChain(testdb2, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)
    next_head_hashes_node_2 = node_2.chain_head_db.get_next_n_head_block_hashes(ZERO_HASH32, 0, 99999)
    
    print([encode_hex(x) for x in next_head_hashes])
    print([encode_hex(x) for x in next_head_hashes_node_2])
    assert(next_head_hashes == next_head_hashes_node_2)
    print("passed chain head hash check")
    
    node_1_historical_root_hashes = node_1.chain_head_db.get_historical_root_hashes()
    node_2_historical_root_hashes = node_2.chain_head_db.get_historical_root_hashes()
    
    #node_2 may have more root hashes because it was imported at a later time.
    #but it should match all of the ones that node_1 has
    for i in range(len(node_1_historical_root_hashes)):
        assert(node_1_historical_root_hashes[i] == node_2_historical_root_hashes[i])
    print('passed historical root hash test') 
    
    for wallet_address in wallet_addresses:
        node_1_account_hash = node_1.get_vm().state.account_db.get_account_hash(wallet_address)
        node_2_account_hash = node_2.get_vm().state.account_db.get_account_hash(wallet_address)
        assert(node_1_account_hash == node_2_account_hash)
        
        node_1_chain = node_1.chaindb.get_all_blocks_on_chain(node_1.get_vm(refresh=False).get_block_class(), wallet_address)
        node_2_chain = node_2.chaindb.get_all_blocks_on_chain(node_2.get_vm(refresh=False).get_block_class(), wallet_address)
        assert(node_1_chain == node_2_chain)
        
        for i in range(len(node_1_chain)):
            assert(node_1_chain[i].hash == node_2_chain[i].hash)
            assert(node_1.chaindb.get_all_descendant_block_hashes(node_1_chain[i].hash) == node_2.chaindb.get_all_descendant_block_hashes(node_2_chain[i].hash))
            
        
    print('passed account hash test, chain test, block decendant tests')
        
        
    
# test_import_chain_overwrite_existing()
# exit()
    
    
def test_import_chain_overwrite_existing_one_at_a_time():
    testdb1 = LevelDB('/home/tommy/.local/share/helios/chain/fuck_279')
    #testdb2 = LevelDB('/home/tommy/.local/share/helios/chain/fuck_280')
    #testdb1 = MemoryDB()
    testdb2 = MemoryDB()
    #testdb1 = JournalDB(LevelDB('/home/tommy/.local/share/helios/chain/fuck_245'))
    #testdb2 = JournalDB(LevelDB('/home/tommy/.local/share/helios/chain/fuck_255'))
    #testdb1 = LevelDB('/home/tommy/.local/share/helios/chain/fuck_26')
    #testdb2 = LevelDB('/home/tommy/.local/share/helios/chain/fuck_27')
    
    from helios.dev_tools import create_dev_test_random_blockchain_database
    
    #create_dev_test_random_blockchain_database(testdb1)
    #create_dev_test_random_blockchain_database(testdb2)
    
    #exit()
    #order of chains
#    ['0xdb4ca426d53b59f60370274ffb19f2268dc33ddf', 
#     '0x885ab3a6cf9f3ccd71a834d5be2eabd08b089e00', 
#     '0xf76eac4faae31632570b886fb27cdf7c9da368ef', 
#     '0x094c08ca4a316c1ec9326ae29872340dcf0028ac', 
#     '0xfc89e5ba946cc4279edf2b090b5e9258c3a11fbb']
    
    testdb1 = JournalDB(testdb1)
    testdb2 = JournalDB(testdb2)
            
    node_1 = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)
    
#    print(node_1.chain_head_db.get_historical_root_hashes())
#    exit()
    
    next_head_hashes = node_1.chain_head_db.get_next_n_head_block_hashes(ZERO_HASH32, 0, 99999)
    #print("IMPORTING {} CHAINS".format(len(next_head_hashes)))
    
    
    i = 0
    wallet_addresses = []
    
    hex_wallet_addresses = ['0xdb4ca426d53b59f60370274ffb19f2268dc33ddf', 
                             '0x885ab3a6cf9f3ccd71a834d5be2eabd08b089e00', 
                             '0xf76eac4faae31632570b886fb27cdf7c9da368ef', 
                             '0x094c08ca4a316c1ec9326ae29872340dcf0028ac', 
                             '0xfc89e5ba946cc4279edf2b090b5e9258c3a11fbb',
                             '0x2bdc0707ccf84350c7a0befea81e5ba1c2a78b3e']
    wallet_addresses = [decode_hex(x) for x in hex_wallet_addresses]
    for next_head_hash in next_head_hashes:
        chain_address = node_1.chaindb.get_chain_wallet_address_for_block_hash(next_head_hash)

        wallet_addresses.append(chain_address)

    #import the first chain
    chain_1 = node_1.chaindb.get_all_blocks_on_chain(node_1.get_vm().get_block_class(), decode_hex('0xdb4ca426d53b59f60370274ffb19f2268dc33ddf'))
    chain_2 = node_1.chaindb.get_all_blocks_on_chain(node_1.get_vm().get_block_class(), decode_hex('0x885ab3a6cf9f3ccd71a834d5be2eabd08b089e00'))
    chain_3 = node_1.chaindb.get_all_blocks_on_chain(node_1.get_vm().get_block_class(), decode_hex('0xf76eac4faae31632570b886fb27cdf7c9da368ef'))
    chain_4 = node_1.chaindb.get_all_blocks_on_chain(node_1.get_vm().get_block_class(), decode_hex('0x094c08ca4a316c1ec9326ae29872340dcf0028ac'))
    chain_5 = node_1.chaindb.get_all_blocks_on_chain(node_1.get_vm().get_block_class(), decode_hex('0xfc89e5ba946cc4279edf2b090b5e9258c3a11fbb'))
    chain_6 = node_1.chaindb.get_all_blocks_on_chain(node_1.get_vm().get_block_class(), decode_hex('0x2bdc0707ccf84350c7a0befea81e5ba1c2a78b3e'))
    #print(chain_to_import)
    
#    for block in chain_2:
#        print(block.number, encode_hex(block.hash))
#    exit()
    
    
    
    node_2 = MainnetChain.from_genesis(testdb2, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)
    #node_2 = MainnetChain(testdb2, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)
    
    print('importing blocks now')
    time.sleep(1)
    
#    node_2.import_chain(block_list = chain_2)
#    node_2.import_chain(block_list = chain_2)
    
    #print("IMPORTING CHAIN number {}".format(i))
#    node_2.import_chain(block_list = chain_1)
#    node_2.import_chain(block_list = chain_2)
#    node_2.import_chain(block_list = chain_3)
#    node_2.import_chain(block_list = chain_4)
#    node_2.import_chain(block_list = chain_5)
#    node_2.import_chain(block_list = chain_6)
    
    print('importing chain 2')
    time.sleep(1)
    node_2.import_chain(block_list = chain_2)
    
    exit()
    print('importing chain 1')
    time.sleep(1)
    node_2.import_chain(block_list = chain_1)
    
    exit()
#    
#    
#    node_2.import_chain(block_list = chain_3)
#    node_2.import_chain(block_list = chain_4)
#    node_2.import_chain(block_list = chain_5)
#    node_2.import_chain(block_list = chain_6)
    
    #exit()
    #now import them all again
    
        
    #####
    #Now we test to make sure both nodes are identical
    #####
    node_2 = MainnetChain(testdb2, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)
    next_head_hashes_node_2 = node_2.chain_head_db.get_next_n_head_block_hashes(ZERO_HASH32, 0, 99999)

    assert(next_head_hashes == next_head_hashes_node_2)
    print("passed chain head hash check")
    
    node_1_historical_root_hashes = node_1.chain_head_db.get_historical_root_hashes()
    node_2_historical_root_hashes = node_2.chain_head_db.get_historical_root_hashes()
    
    #node_2 may have more root hashes because it was imported at a later time.
    #but it should match all of the ones that node_1 has
    for i in range(len(node_1_historical_root_hashes)):
        assert(node_1_historical_root_hashes[i] == node_2_historical_root_hashes[i])
    print('passed historical root hash test') 
    
    for wallet_address in wallet_addresses:
        node_1_account_hash = node_1.get_vm().state.account_db.get_account_hash(wallet_address)
        node_2_account_hash = node_2.get_vm().state.account_db.get_account_hash(wallet_address)
        assert(node_1_account_hash == node_2_account_hash)
        
        node_1_chain = node_1.chaindb.get_all_blocks_on_chain(node_1.get_vm(refresh=False).get_block_class(), wallet_address)
        node_2_chain = node_2.chaindb.get_all_blocks_on_chain(node_2.get_vm(refresh=False).get_block_class(), wallet_address)
        assert(node_1_chain == node_2_chain)
        
        for i in range(len(node_1_chain)):
            assert(node_1_chain[i].hash == node_2_chain[i].hash)
            assert(node_1.chaindb.get_all_descendant_block_hashes(node_1_chain[i].hash) == node_2.chaindb.get_all_descendant_block_hashes(node_2_chain[i].hash))
            
        
    print('passed account hash test, chain test, block decendant tests')
        
        
    
#test_import_chain_overwrite_existing_one_at_a_time()
#exit()


def test_import_chain_overwrite_other_unprocessed_block():
    #testdb = LevelDB('/home/tommy/.local/share/helios/chain/full27')
    testdb = MemoryDB()
    sender_chain = MainnetChain.from_genesis(testdb, SENDER.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)
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

    sender_block_1_imported = sender_chain.import_current_queue_block()


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
    

    
    receiver_chain.create_and_sign_transaction_for_queue_block(
                gas_price=0x01,
                gas=0x0c3500,
                to=RECEIVER2.public_key.to_canonical_address(),
                value=1,
                data=b"",
                v=0,
                r=0,
                s=0
                )
    
    block_1_imported = receiver_chain.import_current_queue_block()
    
    """
    send and receive in same block
    """
    
    receiver2_chain = MainnetChain(testdb, RECEIVER2.public_key.to_canonical_address(), RECEIVER2)
    receiver2_chain.populate_queue_block_with_receive_tx()
    receiver2_chain.import_current_queue_block()
    

    
    
    
    ################
    #2nd different set of blocks
    ################
    
    #testdb = LevelDB('/home/tommy/.local/share/helios/chain/full27')
    testdb2 = MemoryDB()
    sender_chain = MainnetChain.from_genesis(testdb2, SENDER.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)
    """
    Send 2 blocks
    """
    
    sender_chain = MainnetChain(testdb2, SENDER.public_key.to_canonical_address(), SENDER)    
    
    sender_chain.create_and_sign_transaction_for_queue_block(
                gas_price=0x01,
                gas=0x0c3500,
                to=RECEIVER.public_key.to_canonical_address(),
                value=2,
                data=b"",
                v=0,
                r=0,
                s=0
                )
    
    sender_chain.create_and_sign_transaction_for_queue_block(
            gas_price=0x01,
            gas=0x0c3500,
            to=RECEIVER2.public_key.to_canonical_address(),
            value=2,
            data=b"",
            v=0,
            r=0,
            s=0
            )

    
    sender_block_1_imported = sender_chain.import_current_queue_block()
    

    sender_chain = MainnetChain(testdb2, SENDER.public_key.to_canonical_address(), SENDER)
    sender_chain.create_and_sign_transaction_for_queue_block(
                gas_price=0x01,
                gas=0x0c3500,
                to=RECEIVER.public_key.to_canonical_address(),
                value=30000000,
                data=b"",
                v=0,
                r=0,
                s=0
                )
    
    sender_chain.import_current_queue_block()
    
    """
    Receive all tx in one block - genesis block must receive
    """
    receiver_chain = MainnetChain(testdb2, RECEIVER.public_key.to_canonical_address(), RECEIVER)
    receiver_chain.populate_queue_block_with_receive_tx()
    block_0_imported = receiver_chain.import_current_queue_block()
    
    receiver2_chain = MainnetChain(testdb2, RECEIVER2.public_key.to_canonical_address(), RECEIVER2)
    receiver2_chain.populate_queue_block_with_receive_tx()
    receiver2_chain.import_current_queue_block()
    

    
    receiver_chain.create_and_sign_transaction_for_queue_block(
                gas_price=0x01,
                gas=0x0c3500,
                to=RECEIVER2.public_key.to_canonical_address(),
                value=2,
                data=b"",
                v=0,
                r=0,
                s=0
                )
    
    block_1_imported = receiver_chain.import_current_queue_block()
    
    
    """
    make sure we can receive
    """
    receiver_2_chain = MainnetChain(testdb2, RECEIVER2.public_key.to_canonical_address(), RECEIVER2)
    receiver_2_chain.populate_queue_block_with_receive_tx()
    receiver_2_chain.import_current_queue_block()
    
    
    print("doing import test")
    time.sleep(1)
    
    
    ################
    #3rd chain that will import the RECEIVER chain, which will be unprocessed because it needs sender chain first.
    #then it will import the other RECEIVER chain, which will attempt to replace an unprocessed chain
    ###############
    testdb3 = MemoryDB()
    sender_chain_1 = MainnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)
    sender_chain_2 = MainnetChain(testdb2, SENDER.public_key.to_canonical_address(), SENDER)
    sender_chain_3 = MainnetChain(testdb3, SENDER.public_key.to_canonical_address(), SENDER)
    
    db_1_receiver_1_chain = sender_chain_1.chaindb.get_all_blocks_on_chain(sender_chain_1.get_vm().get_block_class(), RECEIVER.public_key.to_canonical_address())
    db_1_receiver_2_chain = sender_chain_1.chaindb.get_all_blocks_on_chain(sender_chain_1.get_vm().get_block_class(), RECEIVER2.public_key.to_canonical_address())
    
    db_2_receiver_1_chain = sender_chain_2.chaindb.get_all_blocks_on_chain(sender_chain_2.get_vm().get_block_class(), RECEIVER.public_key.to_canonical_address())
    
    sender_chain_3.import_chain(block_list = db_1_receiver_1_chain)
    sender_chain_3.import_chain(block_list = db_1_receiver_2_chain)
    
    #at this point, we have an unprocessed receiver chain sitting in sender_chain_3. Lets try to import a different block 0 on that chain
    
    print("overwriting existing unprocessed chain")
    print("receiver_1 chain address = {} with {} blocks".format(encode_hex(RECEIVER.public_key.to_canonical_address()), len(db_1_receiver_1_chain)))
    print("receiver_2 chain address = {} with {} blocks".format(encode_hex(RECEIVER2.public_key.to_canonical_address()), len(db_1_receiver_2_chain)))
    time.sleep(1)
    sender_chain_3.import_block(db_2_receiver_1_chain[0], 
                           save_block_head_hash_timestamp = True, 
                           wallet_address = RECEIVER.public_key.to_canonical_address(), 
                           allow_unprocessed = True, 
                           allow_replacement = True)
        
    
#test_import_chain_overwrite_other_unprocessed_block()
#exit()


def test_chronological_block_import():
    #testdb = LevelDB('/home/tommy/.local/share/helios/chain/full27')
    #testdb1 = LevelDB('/home/tommy/.local/share/helios/chain/fuck_300')
    testdb1 = MemoryDB()
    testdb2 = MemoryDB()
    #testdb1 = JournalDB(LevelDB('/home/tommy/.local/share/helios/chain/fuck_14'))
    #testdb2 = JournalDB(LevelDB('/home/tommy/.local/share/helios/chain/fuck_15'))
    #testdb1 = LevelDB('/home/tommy/.local/share/helios/chain/fuck_26')
    #testdb2 = LevelDB('/home/tommy/.local/share/helios/chain/fuck_27')
    
    from helios.dev_tools import create_dev_test_random_blockchain_database
    
    create_dev_test_random_blockchain_database(testdb1)
    #create_dev_test_random_blockchain_database(testdb2)
    #exit()
    testdb1 = JournalDB(testdb1)
    testdb2 = JournalDB(testdb2)
            
    node_1 = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)
    node_2 = MainnetChain.from_genesis(testdb2, RECEIVER.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)
    
    node_1_historical_root_hashes = node_1.chain_head_db.get_historical_root_hashes()
    node_2_historical_root_hashes = node_2.chain_head_db.get_historical_root_hashes()

    assert(node_1_historical_root_hashes[-2][1] == node_2_historical_root_hashes[0][1])
    
    prev_root_hash = None
    for timestamp_root_hash in reversed(node_1_historical_root_hashes):
        if prev_root_hash is None:
            prev_root_hash = timestamp_root_hash[1]
        else:
            if timestamp_root_hash[1] != prev_root_hash:
                chronological_block_window_to_import = timestamp_root_hash[0]
                break
        
    #timestamp of chronological that we are importing: node_1_historical_root_hashes[-2][0]
    chronological_blocks = node_1.get_all_chronological_blocks_for_window(chronological_block_window_to_import)
    
    print('importing chronological block window')
    time.sleep(1)
    
    #make sure propogate_block_head_hash_timestamp_to_present = True and False works
    node_2.import_chronological_block_window(chronological_blocks, chronological_block_window_to_import)
    
    new_node_2_historical_root_hashes = node_2.chain_head_db.get_historical_root_hashes()

    
    #print('node_1 historical root hashes')
#    print([[x[0], encode_hex(x[1])] for x in node_1_historical_root_hashes])
#    print('node_2 historical root hashes')
#    print([[x[0], encode_hex(x[1])] for x in new_node_2_historical_root_hashes])
    assert(node_1_historical_root_hashes[-1] == new_node_2_historical_root_hashes[-1])
    print('passed chronolgical import test')
        
        
    
#test_chronological_block_import()
#exit()

def importing_p2p_type_block():
    from hvm.utils.rlp import convert_rlp_to_correct_class
    from hvm.rlp.sedes import(
        hash32
    )
    import rlp_cython as rlp
    from rlp_cython import sedes
    from hvm.rlp.transactions import BaseTransaction
    class P2PSendTransaction(rlp.Serializable):
        fields = BaseTransaction._meta.fields
    
    testdb1 = MemoryDB()
    chain = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    transaction = P2PSendTransaction(
                    nonce=1,
                    gas_price=0x01,
                    gas=0x0c3500,
                    to=RECEIVER.public_key.to_canonical_address(),
                    value=0x01,
                    data=b"",
                    v=0,
                    r=0,
                    s=0
                    )
    
    #TODO. link this to the definition in the vm somehow.
    class P2PReceiveTransaction(rlp.Serializable):
        fields =[
            ('sender_block_hash', hash32),
            ('transaction', P2PSendTransaction),
            ('v', sedes.big_endian_int),
            ('r', sedes.big_endian_int),
            ('s', sedes.big_endian_int),
        ]
        
    receive_transaction = P2PReceiveTransaction(sender_block_hash = ZERO_HASH32, transaction = transaction, v=0, r=0, s=0)
    
    block = chain.get_block()
    block = block.add_transaction(transaction)
    block = block.add_receive_transaction(receive_transaction)
    print(block.receive_transactions[0].transaction)
    converted_block = chain.get_vm().convert_block_to_correct_class(block)
    #chain.import_block(block)
    #chain.get_vm().convert_block_to_correct_class(block)
    
    #transaction = convert_rlp_to_correct_class(chain.get_vm().get_block_class().receive_transaction_class, receive_transaction) 
    print(converted_block.receive_transactions[0].transaction)

#importing_p2p_type_block()
#exit()
    
    
def create_new_genesis_params_and_state():
    #
    # GENESIS STATE, HEADER PARAMS
    #

    new_genesis_private_key = GENESIS_PRIVATE_KEY
    print("Ceating new genesis params and state for genesis wallet address:")
    print(new_genesis_private_key.public_key.to_canonical_address())
    total_supply = 100000000 * 10 **18
    new_mainnet_genesis_params = {
        'chain_address': new_genesis_private_key.public_key.to_canonical_address(),
        'parent_hash': constants.GENESIS_PARENT_HASH,
        'transaction_root': constants.BLANK_ROOT_HASH,
        'receive_transaction_root': constants.BLANK_ROOT_HASH,
        'receipt_root': constants.BLANK_ROOT_HASH,
        'bloom': 0,
        'block_number': constants.GENESIS_BLOCK_NUMBER,
        'gas_limit': constants.GENESIS_GAS_LIMIT,
        'gas_used': 0,
        'timestamp': 1543700000,
        'extra_data': constants.GENESIS_EXTRA_DATA,
        'reward_hash': constants.GENESIS_REWARD_HASH,
        'account_balance': total_supply,
    }
    
    
    new_genesis_state = {
        new_genesis_private_key.public_key.to_canonical_address(): {
            "balance": total_supply,
            "code": b"",
            "nonce": 0,
            "storage": {}
        }
    }
        
    testdb1 = MemoryDB()
    genesis_header = MainnetChain.create_genesis_header(testdb1, new_genesis_private_key.public_key.to_canonical_address(), new_genesis_private_key, new_mainnet_genesis_params, new_genesis_state)
    
    print()
    print("New completed and signed genesis header params")
    parameter_names = list(dict(genesis_header._meta.fields).keys())
    header_params = {}
    for parameter_name in parameter_names:
        header_params[parameter_name] = getattr(genesis_header, parameter_name)
    print(header_params)
    print()

    #
    # TPC TEST STATE, HEADER PARAMS
    #
    new_genesis_private_key = TPC_CAP_TEST_GENESIS_PRIVATE_KEY
    print(new_genesis_private_key.public_key.to_canonical_address())

    testdb1 = MemoryDB()
    genesis_header = MainnetChain.create_genesis_header(testdb1,
                                                        new_genesis_private_key.public_key.to_canonical_address(),
                                                        new_genesis_private_key, new_mainnet_genesis_params,
                                                        new_genesis_state)

    print()
    print("New completed and signed tpc test header params")
    parameter_names = list(dict(genesis_header._meta.fields).keys())
    header_params = {}
    for parameter_name in parameter_names:
        header_params[parameter_name] = getattr(genesis_header, parameter_name)
    print(header_params)
    print()





    db = MemoryDB()
    chain = MainnetChain.from_genesis(db,
                                      TPC_CAP_TEST_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                                      header_params,
                                      new_genesis_state,
                                      private_key=TPC_CAP_TEST_GENESIS_PRIVATE_KEY)

    receiver_privkey = keys.PrivateKey(random_private_keys[0])

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=0x0c3500,
        to=receiver_privkey.public_key.to_canonical_address(),
        value=1000,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    imported_block = chain.import_current_queue_block()

    block_dict = imported_block.to_dict()
    print("TPC test block to import")
    print(block_dict)

#
# create_new_genesis_params_and_state()
# exit()

def create_block_params():
    from hvm.chains.mainnet import (
        MAINNET_TPC_CAP_TEST_GENESIS_PARAMS,
        MAINNET_TPC_CAP_TEST_GENESIS_STATE,
        TPC_CAP_TEST_GENESIS_PRIVATE_KEY,
    )

    db = MemoryDB()
    chain = MainnetChain.from_genesis(db,
                                      TPC_CAP_TEST_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                                      MAINNET_TPC_CAP_TEST_GENESIS_PARAMS,
                                      MAINNET_TPC_CAP_TEST_GENESIS_STATE,
                                      private_key=TPC_CAP_TEST_GENESIS_PRIVATE_KEY)

    receiver_privkey = keys.PrivateKey(random_private_keys[0])

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=0x0c3500,
        to=receiver_privkey.public_key.to_canonical_address(),
        value=1000,
        data=b"",
        v=0,
        r=0,
        s=0
    )

    imported_block = chain.import_current_queue_block()

    block_dict = imported_block.to_dict()
    print(block_dict)


# create_block_params()
# sys.exit()
  
def import_genesis():
    testdb1 = MemoryDB()
    testdb1 = LevelDB('/home/tommy/.local/share/helios/chain/fuck_1124')
    #MainnetChain.from_genesis(testdb1, RECEIVER.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)
    
    chain = MainnetChain(testdb1,RECEIVER.public_key.to_canonical_address())
    
    from hvm.exceptions import CanonicalHeadNotFound
    try:
        chain.chaindb.get_canonical_head(wallet_address = GENESIS_WALLET_ADDRESS)
    except CanonicalHeadNotFound:
        # empty chain database
        print("no genesis")
    else:
        print("genesis found")

#import_genesis()
#exit()




def test_min_allowed_gas_system():
    #testdb = LevelDB('/home/tommy/.local/share/helios/chain/full27')
    #testdb1 = LevelDB('/home/tommy/.local/share/helios/chain/fuck_160')
    testdb1 = MemoryDB()
    
    from helios.dev_tools import create_dev_test_random_blockchain_database
    
    create_dev_test_random_blockchain_database(testdb1)

    #testdb1 = JournalDB(testdb1)
            
    node_1 = MainnetChain(testdb1, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    while True:
        print('loading historical transactions per centisecond')
        historical_tpc = node_1.chaindb.load_historical_tx_per_centisecond(sort = True)
        print(historical_tpc)
        
        print('loading historical minimum gas price')
        historical_min_gas_price = node_1.chaindb.load_historical_minimum_gas_price(sort = True)
        print(historical_min_gas_price)
        
        print('loading historical network tpc max capability')
        historical_network_tpc_capability = node_1.chaindb.load_historical_network_tpc_capability(sort = True)
        print(historical_network_tpc_capability)
        
        node_1.update_current_network_tpc_capability(3000, True)
        time.sleep(5)
    sys.exit()
    
    #need to check that network max tpc capability is up to date before running this or it will throw an error
    node_1.chaindb.save_current_historical_network_tpc_capability(5)
    
    node_1.update_tpc_from_chronological(update_min_gas_price = True)
    
    print('loading historical transactions per centisecond')
    historical_tpc = node_1.chaindb.load_historical_tx_per_centisecond(sort = True)
    print(historical_tpc)
    
    print('loading historical minimum gas price')
    historical_min_gas_price = node_1.chaindb.load_historical_minimum_gas_price(sort = True)
    print(historical_min_gas_price)
    
    print('loading historical network tpc max capability')
    historical_network_tpc_capability = node_1.chaindb.load_historical_network_tpc_capability(sort = True)
    print(historical_network_tpc_capability)
    
    
    #next, lets manually increase the tpc and make sure gas price increases as expected
    print('manually increasing tx per centisecond in db')
    
    current_centisecond = int(time.time()/100) * 100
    historical_tx_per_centisecond = []
    start_tpc = 0
    
    i = 0
    for timestamp in range(current_centisecond-100*50, current_centisecond+100, 100):
        if i < 25:
            historical_tx_per_centisecond.append([timestamp, start_tpc+i*2])
        else:
            amount = 20-(i-25)*2
            if amount <= 1:
                amount = 1
            historical_tx_per_centisecond.append([timestamp, amount])
        i+=1
    
    node_1.chaindb.save_historical_tx_per_centisecond(historical_tx_per_centisecond, de_sparse = False)
    node_1.chaindb.recalculate_historical_mimimum_gas_price(current_centisecond-100*20)
    
    print('loading historical transactions per centisecond')
    historical_tpc = node_1.chaindb.load_historical_tx_per_centisecond(sort = True)
    print(historical_tpc)
    
    print('loading historical minimum gas price')
    historical_min_gas_price = node_1.chaindb.load_historical_minimum_gas_price(sort = True)
    print(historical_min_gas_price)
    
    print('loading historical network tpc max capability')
    historical_network_tpc_capability = node_1.chaindb.load_historical_network_tpc_capability(sort = True)
    print(historical_network_tpc_capability)
    
    
    
#test_min_allowed_gas_system()
#exit()

import asyncio





async def test_process_pool_executor():
    
    def validate_block_specification(block):
        '''
        This validates everything we can without looking at the blockchain database. It doesnt need to assume
        that we have the block that sent the transactions.
        This that this can check:
            block signature
            send transaction signatures
            receive transaction signatures
            signatures of send transaction within receive transactions
            send transaction root matches transactions
            receive transaction root matches transactions
            
        '''
        
        for i in range(1):    
            block.header.check_signature_validity()
            
            for transaction in block.transactions:
                transaction.validate()
                
            for receive_transaction in block.receive_transactions:
                receive_transaction.validate()
            

    testdb = MemoryDB()
    
    sender_chain = MainnetChain.from_genesis(testdb, SENDER.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)
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
            value=2,
            data=b"",
            v=0,
            r=0,
            s=0
            )
    
    sender_chain.create_and_sign_transaction_for_queue_block(
            gas_price=0x01,
            gas=0x0c3500,
            to=RECEIVER2.public_key.to_canonical_address(),
            value=3,
            data=b"",
            v=0,
            r=0,
            s=0
            )
        
    sender_chain.create_and_sign_transaction_for_queue_block(
            gas_price=0x01,
            gas=0x0c3500,
            to=RECEIVER2.public_key.to_canonical_address(),
            value=4,
            data=b"",
            v=0,
            r=0,
            s=0
            )
        
    sender_chain.create_and_sign_transaction_for_queue_block(
            gas_price=0x01,
            gas=0x0c3500,
            to=RECEIVER2.public_key.to_canonical_address(),
            value=5,
            data=b"",
            v=0,
            r=0,
            s=0
            )
    
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
            value=2,
            data=b"",
            v=0,
            r=0,
            s=0
            )
    
    sender_chain.create_and_sign_transaction_for_queue_block(
            gas_price=0x01,
            gas=0x0c3500,
            to=RECEIVER2.public_key.to_canonical_address(),
            value=3,
            data=b"",
            v=0,
            r=0,
            s=0
            )
        
    sender_chain.create_and_sign_transaction_for_queue_block(
            gas_price=0x01,
            gas=0x0c3500,
            to=RECEIVER2.public_key.to_canonical_address(),
            value=4,
            data=b"",
            v=0,
            r=0,
            s=0
            )
        
    sender_chain.create_and_sign_transaction_for_queue_block(
            gas_price=0x01,
            gas=0x0c3500,
            to=RECEIVER2.public_key.to_canonical_address(),
            value=5,
            data=b"",
            v=0,
            r=0,
            s=0
            )

    sender_block_1_imported = sender_chain.import_current_queue_block()
    
    from helios.utils.mp import (
        async_method,
    )
    
    
    
#    import pickle
#    pickle.dump(validate_block_specification, open('test.txt','wb'))
#    exit()
    start_time = time.time()
    result = sender_chain.validate_block_specification(sender_block_1_imported)
    #result = validate_block_specification(sender_block_1_imported)
    end_time = time.time()
    print(result)
    print("executing normally it took {}".format(end_time-start_time))
    
    start_time = time.time()
    
    result = await loop.run_in_executor(
            None,
            validate_block_specification,
            sender_block_1_imported,
        )
    end_time = time.time()
    print(result)
    print("executing in thread pool executor it took {}".format(end_time-start_time))
    


# test_process_pool_executor()
# sys.exit()
# loop = asyncio.get_event_loop()
# loop.run_until_complete(test_process_pool_executor())

#@profile(sortby='cumulative')
def get_node_tpc_cap():
    testdb = MemoryDB()

    sender_chain = MainnetChain.from_genesis(testdb, SENDER.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS,
                                             MAINNET_GENESIS_STATE)

    tpc_cap = sender_chain.get_local_tpc_cap()

    print("tpc_cap = {}".format(tpc_cap))


# get_node_tpc_cap()
# sys.exit()


def test_fast_rlp():
    import crlp
    import rlp_cython as rlp
    from crlp.sedes.serializable import Serializable
    from crlp.sedes import big_endian_int, binary, Binary, BigEndianInt, CountableList
    import random
    import sys
    from msgpack_rlp import packb, unpackb, Packer

    address = Binary.fixed_length(20, allow_empty=True)
    hash32 = Binary.fixed_length(32)
    int32 = BigEndianInt(32)
    int256 = BigEndianInt(256)
    trie_root = Binary.fixed_length(32, allow_empty=True)

    class BlockHeader(Serializable):
        fields = [
            ('parent_hash', hash32),
            ('transaction_root', trie_root),
            ('receive_transaction_root', trie_root),
            ('receipt_root', trie_root),
            ('bloom', int256),
            ('block_number', big_endian_int),
            ('gas_limit', big_endian_int),
            ('gas_used', big_endian_int),
            ('timestamp', big_endian_int),
            ('extra_data', binary),
            ('account_hash', hash32),
            ('v', big_endian_int),
            ('r', big_endian_int),
            ('s', big_endian_int),
        ]

    class HeliosTestnetTransaction(Serializable):
        fields = [
            ('nonce', big_endian_int),
            ('gas_price', big_endian_int),
            ('gas', big_endian_int),
            ('to', address),
            ('value', big_endian_int),
            ('data', binary),
            ('v', big_endian_int),
            ('r', big_endian_int),
            ('s', big_endian_int),
        ]

    class HeliosTestnetReceiveTransaction(Serializable):

        fields = [
            ('sender_block_hash', hash32),
            ('send_transaction_hash', hash32)
        ]


    class HeliosTestnetBlock(Serializable):
        transaction_class = HeliosTestnetTransaction
        receive_transaction_class = HeliosTestnetReceiveTransaction

        fields = [
            ('header', BlockHeader),
            ('transactions', CountableList(transaction_class)),
            ('receive_transactions', CountableList(receive_transaction_class))
        ]

    class rlp_test(rlp.sedes.Serializable):
        transaction_class = HeliosTestnetTransaction
        receive_transaction_class = HeliosTestnetReceiveTransaction

        fields = [
            ('header', big_endian_int),
            ('transactions', CountableList(big_endian_int)),
            ('receive_transactions', CountableList(big_endian_int))
        ]

    class crlp_test(Serializable):
        transaction_class = HeliosTestnetTransaction
        receive_transaction_class = HeliosTestnetReceiveTransaction

        fields = [
            ('header', big_endian_int),
            ('transactions', CountableList(big_endian_int)),
            ('receive_transactions', CountableList(big_endian_int))
        ]

    # for i in range(1000):
    #     print(i)
    #     rand_1 = random.randint(100,1000)
    #     rand_list_1 = list(range(rand_1,rand_1*10))
    #     rand_list_2 = []
    #     rlp_test_obj = rlp_test(rand_1, rand_list_1, rand_list_2)
    #     crlp_test_obj = crlp_test(rand_1, rand_list_1, rand_list_2)
    #
    #     rlp_block_hash = rlp.encode(rlp_test_obj)
    #
    #     crlp_block_hash = crlp.encode(rlp_test_obj, sedes=rlp_test_obj)
    #
    #     if rlp_block_hash != crlp_block_hash:
    #         print(rlp_block_hash)
    #         print(crlp_block_hash)
    #         sys.exit()

    # rlp_sede_serialized_block = [[b'\xe8m\xc3\xb8a<\xd5\xdcQl\xac=V\xba\xd1\x9f\xceP?\x9c\x16}\x8cqW\x1fX\xdc \xd6P\x0e', b'A\r\x14\xb5\xb9\xf2^3\xb1\xa7!\x1c\xdd\x81l\x07\x04\xc0\x03\x00q\x90\xae\xbe\x8f\x8a\x7f$]k\xf9\xb2', b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', b'\x10\x0f36\x86-"pk\xbe&\xd6~Z\xbf\x90\xf8\xf2^\xc5\xa2,DF\x83[k\xea\xa6\xb5\x956', b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', b'\x01', b'?2\x18', b'\x01\x9a(', b'[\x94\x83,', b'', b"'=tS.\xa4\xe3/\xf1\x12\x0c\xd6\xac\xc3\xdf'\x9d\x1f\xa2h\x1d=r\x90qL&>\xed\xdd\x96\xcf", b'&', b'\xba\x87Wi\x14\xa0\xd2\xda\x94\xcfC\xca{\xfc\xa2\xc4\xb0\xfc\xa5\x01~\x9a,55}\xc6e\xd9\xb2GH', b'H\x07\xa4\x0e6\xe4\xf5\xf1myT7\x7fF\xc0\xf4w&\x08^\x1a\xf0&\x0f\x02\x0378)\x93]X'], [[b'', b'\x01', b'\x0c5\x00', b'\xd6\x8f>\xbe\xcd\xedF\xbc\xc8\xe1J\x90\x1c#{\xc4fB\xc8\x06', b'\x01', b'', b'&', b'\xefA\xbbh#d\xc8>C\xe8]>\x1e!S_\xcb\xfdR\xd7\\[\xd6\x91c\x14\xa3\x0c\x15U<G', b'9f\x99d\xb9\x14\x81k\xad7tw\xb3\xeb,\xf4\xde\x8a\xbbn],\x98\xa2\xb5J]\xad\xa7A\xael'], [b'\x01', b'\x01', b'\x0c5\x00', b'\xd6\x8f>\xbe\xcd\xedF\xbc\xc8\xe1J\x90\x1c#{\xc4fB\xc8\x06', b'\x01', b'', b'&', b'F\xf5\xc5\x11x<\x05b\xcd\x03/\xace\x97\x185s"\x1d7\x90h\xb3\x19\x1as\x9c\x98\xc6\xd0{3', b'E5\xe5\x9e\x84\xb0\xfd\xcd\x1b/&\xfa\x8c\xe9\xdb2\x04A\xcd3{\xda\xc0`\x1az~]!\x15\x86\x85'], [b'\x02', b'\x01', b'\x0c5\x00', b'\xd6\x8f>\xbe\xcd\xedF\xbc\xc8\xe1J\x90\x1c#{\xc4fB\xc8\x06', b'\x01', b'', b'%', b'\x84\xe0|\xaa\xc2\x90\xfc\xf5+\x9f\xe1nh\xc24WY\x07i\xb9\x80\xee\x1e\x00\xdc\xbfe /y\x9f\x84', b'\x06\xbf\x90\xaa\xff@\x9d\xab"\xb0\xb0\x99\xd5\x0e\xf8\xf4\x12\xc9\n\x10\x13\xfd\xe8\x0c\xf9\x8b\x1f\xa394_c'], [b'\x03', b'\x01', b'\x0c5\x00', b'\xd6\x8f>\xbe\xcd\xedF\xbc\xc8\xe1J\x90\x1c#{\xc4fB\xc8\x06', b'\x01', b'', b'&', b'ml6\\\x02\xfcw\x9e\xc1\xb5\x8b\x80\xca2\\P"\xabX\x16\xca9Pc\x03\x1a\xd6\x1c\xc7\x00\x9e\xa3', b"g\xd1\xa7J\xbb\x93\xaa\x1e\x11]\x95\xc0<\xfa_\xf4!\x8a(\x92!'\x87\x95\xe3I\x00T\x92\xe5\xf5\xc9"], [b'\x04', b'\x01', b'\x0c5\x00', b'\xd6\x8f>\xbe\xcd\xedF\xbc\xc8\xe1J\x90\x1c#{\xc4fB\xc8\x06', b'\x01', b'', b'%', b'\xfe\x853O\xea5\xf5"\x1dN\xd9\xd8{\x16?\x12\x89\xf8\x90\xdd\x9a\x80\x83\xfdv\x97b\xe7\xe3\x1f\xb1\x86', b's\xe8\n1\x87\xa1\x98\xb8\xf0\x14\xf4qw\x1a\xb7\xb4\xee\xccU\x9dv\xa4N\x8a\x92yzZ\x81J>\xae']], []]
    # crlp_sede_serialized_block = rlp_sede_serialized_block
    #
    # rlp_block_hash = rlp.encode(rlp_sede_serialized_block)
    #
    # #crlp_block_hash = crlp.encode(crlp_sede_serialized_block, infer_serializer=False)
    # crlp_block_hash = packb(crlp_sede_serialized_block)
    #
    # if rlp_block_hash != crlp_block_hash:
    #     print('didn"t match')
    #     print(rlp_block_hash)
    #     print(crlp_block_hash)



    testdb = MemoryDB()
    start = time.time()
    sender_chain = MainnetChain.from_genesis(testdb, SENDER.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)


    previous_result = None
    length = []

    results = []
    sender_chain = MainnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)
    block_class = sender_chain.get_vm().get_block_class()
    for i in range(10):
        print(i)
        for i in range(5):
            transaction = sender_chain.create_and_sign_transaction_for_queue_block(
                gas_price=0x01,
                gas=0x0c3500,
                to=RECEIVER2.public_key.to_canonical_address(),
                value=1,
                data=b"",
                v=0,
                r=0,
                s=0
            )

            # rlp_tx_hash = rlp.encode(transaction)
            # crlp_tx_hash = crlp.encode(transaction)
            #
            # assert(rlp_tx_hash == crlp_tx_hash)


        block = sender_chain.import_current_queue_block()

        rlp_sede_serialized_block = [[b'\xe8m\xc3\xb8a<\xd5\xdcQl\xac=V\xba\xd1\x9f\xceP?\x9c\x16}\x8cqW\x1fX\xdc \xd6P\x0e', b'A\r\x14\xb5\xb9\xf2^3\xb1\xa7!\x1c\xdd\x81l\x07\x04\xc0\x03\x00q\x90\xae\xbe\x8f\x8a\x7f$]k\xf9\xb2', b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', b'\x10\x0f36\x86-"pk\xbe&\xd6~Z\xbf\x90\xf8\xf2^\xc5\xa2,DF\x83[k\xea\xa6\xb5\x956', b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', b'\x01', b'?2\x18', b'\x01\x9a(', b'[\x94\x83,', b'', b"'=tS.\xa4\xe3/\xf1\x12\x0c\xd6\xac\xc3\xdf'\x9d\x1f\xa2h\x1d=r\x90qL&>\xed\xdd\x96\xcf", b'&', b'\xba\x87Wi\x14\xa0\xd2\xda\x94\xcfC\xca{\xfc\xa2\xc4\xb0\xfc\xa5\x01~\x9a,55}\xc6e\xd9\xb2GH', b'H\x07\xa4\x0e6\xe4\xf5\xf1myT7\x7fF\xc0\xf4w&\x08^\x1a\xf0&\x0f\x02\x0378)\x93]X'], [[b'', b'\x01', b'\x0c5\x00', b'\xd6\x8f>\xbe\xcd\xedF\xbc\xc8\xe1J\x90\x1c#{\xc4fB\xc8\x06', b'\x01', b'', b'&', b'\xefA\xbbh#d\xc8>C\xe8]>\x1e!S_\xcb\xfdR\xd7\\[\xd6\x91c\x14\xa3\x0c\x15U<G', b'9f\x99d\xb9\x14\x81k\xad7tw\xb3\xeb,\xf4\xde\x8a\xbbn],\x98\xa2\xb5J]\xad\xa7A\xael'], [b'\x01', b'\x01', b'\x0c5\x00', b'\xd6\x8f>\xbe\xcd\xedF\xbc\xc8\xe1J\x90\x1c#{\xc4fB\xc8\x06', b'\x01', b'', b'&', b'F\xf5\xc5\x11x<\x05b\xcd\x03/\xace\x97\x185s"\x1d7\x90h\xb3\x19\x1as\x9c\x98\xc6\xd0{3', b'E5\xe5\x9e\x84\xb0\xfd\xcd\x1b/&\xfa\x8c\xe9\xdb2\x04A\xcd3{\xda\xc0`\x1az~]!\x15\x86\x85'], [b'\x02', b'\x01', b'\x0c5\x00', b'\xd6\x8f>\xbe\xcd\xedF\xbc\xc8\xe1J\x90\x1c#{\xc4fB\xc8\x06', b'\x01', b'', b'%', b'\x84\xe0|\xaa\xc2\x90\xfc\xf5+\x9f\xe1nh\xc24WY\x07i\xb9\x80\xee\x1e\x00\xdc\xbfe /y\x9f\x84', b'\x06\xbf\x90\xaa\xff@\x9d\xab"\xb0\xb0\x99\xd5\x0e\xf8\xf4\x12\xc9\n\x10\x13\xfd\xe8\x0c\xf9\x8b\x1f\xa394_c'], [b'\x03', b'\x01', b'\x0c5\x00', b'\xd6\x8f>\xbe\xcd\xedF\xbc\xc8\xe1J\x90\x1c#{\xc4fB\xc8\x06', b'\x01', b'', b'&', b'ml6\\\x02\xfcw\x9e\xc1\xb5\x8b\x80\xca2\\P"\xabX\x16\xca9Pc\x03\x1a\xd6\x1c\xc7\x00\x9e\xa3', b"g\xd1\xa7J\xbb\x93\xaa\x1e\x11]\x95\xc0<\xfa_\xf4!\x8a(\x92!'\x87\x95\xe3I\x00T\x92\xe5\xf5\xc9"], [b'\x04', b'\x01', b'\x0c5\x00', b'\xd6\x8f>\xbe\xcd\xedF\xbc\xc8\xe1J\x90\x1c#{\xc4fB\xc8\x06', b'\x01', b'', b'%', b'\xfe\x853O\xea5\xf5"\x1dN\xd9\xd8{\x16?\x12\x89\xf8\x90\xdd\x9a\x80\x83\xfdv\x97b\xe7\xe3\x1f\xb1\x86', b's\xe8\n1\x87\xa1\x98\xb8\xf0\x14\xf4qw\x1a\xb7\xb4\xee\xccU\x9dv\xa4N\x8a\x92yzZ\x81J>\xae']], []]
        crlp_sede_serialized_block = rlp_sede_serialized_block
        #rlp_sede_serialized_block = block_class.serialize(block)
        #crlp_sede_serialized_block = HeliosTestnetBlock.serialize(block)

        #rlp_block_hash = rlp.encode(rlp_sede_serialized_block)

        packer = Packer(autoreset=False)
        crlp_block_hash = packer.pack(crlp_sede_serialized_block)
        length.append(packer.get_length())
        print(length)
        packer.reset()

        results.append(crlp_block_hash)

        if previous_result is None:
            previous_result = crlp_block_hash
        else:
            if previous_result != crlp_block_hash:
                print('crlp"s result changed')
                print(crlp_block_hash)
                print(length)

                #sys.exit()
    for result in results:
        print(result)



        # if rlp_block_hash != crlp_block_hash:
        #     print(rlp_block_hash)
        #     print(crlp_block_hash)
        #
        #     print('trying again')
        #
        #     for i in range(1000):
        #         print(i)
        #         rlp_block_hash = rlp.encode(block)
        #
        #         crlp_block_hash = crlp.encode(block, sedes=HeliosTestnetBlock)
        #
        #         if rlp_block_hash != crlp_block_hash:
        #             #rlp_sede_serialized_block = block_class.serialize(block)
        #             #clp_sede_serialized_block = HeliosTestnetBlock.serialize(block)
        #
        #             print(rlp_sede_serialized_block)
        #             print(crlp_sede_serialized_block)
        #             if rlp_sede_serialized_block != crlp_sede_serialized_block:
        #                 print('fuck')
        #             sys.exit()



# test_fast_rlp()
# sys.exit()



def test_trie():
    from trie import (
        HexaryTrie,
    )
    from hvm.constants import (
        BLANK_ROOT_HASH,
    )

    import rlp_cython as rlp

    kv_store = {}
    trie = HexaryTrie(kv_store, BLANK_ROOT_HASH)

    with trie.squash_changes() as memory_trie:

        index_key = rlp.encode(1, sedes=rlp.sedes.big_endian_int)

        item = rlp.encode('test1')
        memory_trie[index_key] = item
        print(encode_hex(memory_trie.root_hash))

        index_key = rlp.encode(2, sedes=rlp.sedes.big_endian_int)
        item = rlp.encode('test2')
        memory_trie[index_key] = item

        print(encode_hex(memory_trie.root_hash))

        index_key = rlp.encode(3, sedes=rlp.sedes.big_endian_int)
        item = rlp.encode('test3')
        memory_trie[index_key] = item

    print(encode_hex(trie.root_hash))

# test_trie()
# sys.exit()


def test_block_hash_to_compare_to_js():


    testdb = LevelDB('/home/tommy/.local/share/helios/instance_test/mainnet/chain/full/')
    testdb = JournalDB(testdb)

    """
    Send 2 blocks
    """

    sender_chain = MainnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)

    transaction = sender_chain.create_and_sign_transaction_for_queue_block(
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
        to=RECEIVER.public_key.to_canonical_address(),
        value=1,
        data=b"",
        v=0,
        r=0,
        s=0
    )
    #
    # print(encode_hex(transaction.hash))
    # transaction_parts = rlp.decode(rlp.encode(transaction, sedes = transaction.__class__))
    #
    # print(encode_hex(transaction_parts[0]))
    # print(encode_hex(transaction_parts[1]))
    # print(encode_hex(transaction_parts[2]))
    # print(encode_hex(transaction_parts[3]))
    # print(encode_hex(transaction_parts[4]))
    # print(encode_hex(transaction_parts[5]))
    # print(encode_hex(transaction_parts[6]))
    # print(encode_hex(transaction_parts[7]))
    # print(encode_hex(transaction_parts[8]))
    #
    #
    # sys.exit()

    # sender_chain.create_and_sign_transaction_for_queue_block(
    #     gas_price=0x01,
    #     gas=0x0c3500,
    #     to=RECEIVER2.public_key.to_canonical_address(),
    #     value=2,
    #     data=b"",
    #     v=0,
    #     r=0,
    #     s=0
    # )
    #
    # sender_chain.create_and_sign_transaction_for_queue_block(
    #     gas_price=0x01,
    #     gas=0x0c3500,
    #     to=RECEIVER2.public_key.to_canonical_address(),
    #     value=3,
    #     data=b"",
    #     v=0,
    #     r=0,
    #     s=0
    # )


    imported_block = sender_chain.import_current_queue_block()

    print('printing details')
    print(encode_hex(imported_block.header.micro_header_hash))
    print(encode_hex(imported_block.header.transaction_root))
    print(encode_hex(imported_block.header.receive_transaction_root))
    print('timestamp = ', imported_block.header.timestamp)

    # print("printing header details")
    #
    # header_parts = rlp.decode(rlp.encode(imported_block.header, sedes=imported_block.header.__class__))
    #
    # print(encode_hex(header_parts[0]))
    # print(encode_hex(header_parts[1]))
    # print(encode_hex(header_parts[2]))
    # print(encode_hex(header_parts[3]))
    # print(encode_hex(header_parts[4]))
    # print(encode_hex(header_parts[5]))
    # print(encode_hex(header_parts[6]))
    # print(encode_hex(header_parts[7]))
    # print(encode_hex(header_parts[8]))
    # print(encode_hex(header_parts[9]))
    # print(encode_hex(header_parts[10]))
    # print(encode_hex(header_parts[11]))
    # print(encode_hex(header_parts[12]))
    # print(encode_hex(header_parts[13]))


# test_block_hash_to_compare_to_js()
# sys.exit()

#toHex = lambda x:"".join([hex(ord(c))[2:].zfill(2) for c in x])

def test_create_block_from_JSON_dict():

    block_dict = {'header': {'parent_hash': '0x07251385fb67815828466d62b1e49dc9d2484a81172fdc12fe0d656f9033cd2f',
                'transaction_root': '0x334a6dcf77252e4345b7fde2c7d138b50d8bbce0de972289074375e8227de614',
                'receive_transaction_root': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421',
                'block_number': '0x02', 'timestamp': '0x5ba45a71', 'extra_data': '0x', 'v': '0x25',
                'r': '0x2477311158537c316a222cfb78b1e19b316b0743c1990e40eb738ce2c0caa930',
                's': '0x0c972037a52a9b5d3215a37016f4cf96b00988f9062392031b31beb1a438002c', 'gas_limit': 4141592},
     'transactions': [
         {'nonce': '0x02', 'gas_price': '0x01', 'gas': '0x0c3500', 'to': '0x0d1630cb77c00d95f7fa32bccfe80043639681be',
          'value': '0x01', 'data': '0x', 'v': '0x25',
          'r': '0xe136585db4d3bf5a7438094bbf7e20515a04a2c5ce8c17588ee4340a88edb5ae',
          's': '0x4e861fb36dc3cf0731dba052c0c8d0989e78ae135433f3a3fce5b55b5af86dab'}], 'receive_transactions': []}

    block_dict['header']['parent_hash'] = decode_hex(block_dict['header']['parent_hash'])
    block_dict['header']['transaction_root'] = decode_hex(block_dict['header']['transaction_root'])
    block_dict['header']['receive_transaction_root'] = decode_hex(block_dict['header']['receive_transaction_root'])
    block_dict['header']['extra_data'] = decode_hex(block_dict['header']['extra_data'])
    block_dict['header']['block_number'] = int(block_dict['header']['block_number'], 16)
    block_dict['header']['timestamp'] = int(block_dict['header']['timestamp'], 16)
    block_dict['header']['v'] = int(block_dict['header']['v'], 16)
    block_dict['header']['r'] = int(block_dict['header']['r'], 16)
    block_dict['header']['s'] = int(block_dict['header']['s'], 16)

    for i in range(len(block_dict['transactions'])):
        block_dict['transactions'][i]['nonce'] = int(block_dict['transactions'][i]['nonce'], 16)
        block_dict['transactions'][i]['gas_price'] = int(block_dict['transactions'][i]['gas_price'], 16)
        block_dict['transactions'][i]['gas'] = int(block_dict['transactions'][i]['gas'], 16)
        block_dict['transactions'][i]['value'] = int(block_dict['transactions'][i]['value'], 16)
        block_dict['transactions'][i]['v'] = int(block_dict['transactions'][i]['v'], 16)
        block_dict['transactions'][i]['r'] = int(block_dict['transactions'][i]['r'], 16)
        block_dict['transactions'][i]['s'] = int(block_dict['transactions'][i]['s'], 16)

        block_dict['transactions'][i]['to'] = decode_hex(block_dict['transactions'][i]['to'])
        block_dict['transactions'][i]['data'] = decode_hex(block_dict['transactions'][i]['data'])

    for i in range(len(block_dict['receive_transactions'])):
        block_dict['receive_transactions'][i]['parent_block_hash'] = decode_hex(block_dict['receive_transactions'][i]['parent_block_hash'])
        block_dict['receive_transactions'][i]['transaction_hash'] = decode_hex(block_dict['receive_transactions'][i]['transaction_hash'])

    print(block_dict)


    testdb = MemoryDB()
    sender_chain = MainnetChain.from_genesis(testdb, SENDER.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)


    block = sender_chain.get_vm().get_block_class().from_dict(block_dict)

    #print(hex(int('0xe136585db4d3bf5a7438094bbf7e20515a04a2c5ce8c17588ee4340a88edb5ae', 16)))
    #print(int_to_big_endian(0xe136585db4d3bf5a7438094bbf7e20515a04a2c5ce8c17588ee4340a88edb5ae))

    print(block.transactions[0].sender)

    print()
    #
    # for key, val in block_dict['header'].items():
    #     print(key, val)
    #
    # for key, val in block_dict['header'].items():
    #     print(key, decode_hex(val))



# test_create_block_from_JSON_dict()
# sys.exit()
#


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
    # peer_score = chain.consensus_db.get_signed_peer_score(GENESIS_PRIVATE_KEY,
    #                                                      private_keys[1].public_key.to_canonical_address())
    #
    #
    # # fields = [
    # #     ('recipient_node_wallet_address', address),
    # #     ('score', f_big_endian_int),  # a score out of 1,000,000
    # #     ('since_block_number', f_big_endian_int),
    # #     ('timestamp', f_big_endian_int),
    # #     ('head_hash_of_sender_chain', hash32),
    # #     ('v', big_endian_int),
    # #     ('r', big_endian_int),
    # #     ('s', big_endian_int),
    # # ]
    # #
    # print(peer_score.recipient_node_wallet_address)
    # print(peer_score.score)
    # print(peer_score.since_block_number)
    # print(peer_score.timestamp)
    # print(peer_score.head_hash_of_sender_chain)
    # print(peer_score.v)
    # print(peer_score.r)
    # print(peer_score.s)
    #
    #



    #now create that function to verify the reward_bundle

    #check to see if the order of proofs effects the header hash. if it does we need to put rewards somewhere else and use
    # root hash of the proofs or something. Create a function that creates reward bundle hash. Make sure it orders
    # the proofs in some predefined way.

    #edit chain import block to validate reward block, then if you get a RewardProofSenderBlockMissing error, save as unprocessed with lookups

    #then edit vm import_block to add the balance to the account

    #then program consensus to allow nodes to ask other nodes for proof

    #wherever we are checking to make sure the block has transactions, we can relieve that and allow blocks with no transactions
    #if they have a reward bundle.

    #persist reward bundles

    #save the last reward block lookup

    #when we load blocks, we need to load the reward bundles too




#
# test_block_rewards_system()
# sys.exit()



def test_smart_contract_deploy_system():
    from helios.dev_tools import create_dev_fixed_blockchain_database

    from hvm.rlp.receipts import (
        Receipt,
    )
    from solc import compile_source, compile_files, link_code, get_solc_version

    from eth_utils import to_int

    from hvm.utils.address import generate_contract_address

    from pathlib import Path
    home = str(Path.home())

    os.environ["SOLC_BINARY"] = home + "/.py-solc/solc-v0.4.25/bin/solc"

    try:
        get_solc_version()
    except Exception:
        print("Solc not found. Installing")
        from solc import install_solc
        install_solc('v0.4.25')


    from web3 import Web3

    W3_TX_DEFAULTS = {'gas': 0, 'gasPrice': 0}

    from hvm.constants import CREATE_CONTRACT_ADDRESS

    # testdb = LevelDB('/home/tommy/.local/share/helios/instance_test/mainnet/chain/full/')
    # testdb = JournalDB(testdb)
    testdb = MemoryDB()

    private_keys = []
    for i in range(10):
        private_keys.append(get_primary_node_private_helios_key(i))

    now = int(time.time())
    coin_mature_time = constants.COIN_MATURE_TIME_FOR_STAKING
    key_balance_dict = {
        private_keys[0]: (1000000000000, now - coin_mature_time * 10 - 100),
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

    chain = MainnetChain(testdb, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    for private_key, balance_time in key_balance_dict.items():
        assert(chain.get_vm().state.account_db.get_balance(private_key.public_key.to_canonical_address()) == balance_time[0])

    SOLIDITY_SRC_FILE = 'contract_data/erc20.sol'
    EXPECTED_TOTAL_SUPPLY = 10000000000000000000000

    compiled_sol = compile_files([SOLIDITY_SRC_FILE])

    contract_interface = compiled_sol['{}:SimpleToken'.format(SOLIDITY_SRC_FILE)]

    w3 = Web3()

    SimpleToken = w3.eth.contract(
        abi=contract_interface['abi'],
        bytecode=contract_interface['bin']
    )

    # Build transaction to deploy the contract
    w3_tx1 = SimpleToken.constructor().buildTransaction(W3_TX_DEFAULTS)

    max_gas = 20000000

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=max_gas,
        to=CREATE_CONTRACT_ADDRESS,
        value=0,
        data=decode_hex(w3_tx1['data']),
        v=0,
        r=0,
        s=0
    )

    #time.sleep(1)
    print("deploying smart contract")

    initial_balance = chain.get_vm().state.account_db.get_balance(GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    imported_block = chain.import_current_queue_block()
    final_balance = chain.get_vm().state.account_db.get_balance(GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    gas_used = to_int(chain.chaindb.get_receipts(imported_block.header, Receipt)[0].gas_used)
    assert ((initial_balance - final_balance) == gas_used)

    print(GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    print(generate_contract_address(GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), imported_block.transactions[0].nonce))
    print(chain.chaindb.get_receipts(imported_block.header, Receipt)[0].logs[0].address)
    exit()

    #contractAddress

    print("Used the correct amount of gas.")

    print('done')


    #now we need to add the block to the smart contract
    list_of_smart_contracts = chain.get_vm().state.account_db.get_smart_contracts_with_pending_transactions()
    deployed_contract_address = list_of_smart_contracts[0]
    print(list_of_smart_contracts)

    chain = MainnetChain(testdb, deployed_contract_address, private_keys[0])

    chain.populate_queue_block_with_receive_tx()
    imported_block = chain.import_current_queue_block()

    list_of_smart_contracts = chain.get_vm().state.account_db.get_smart_contracts_with_pending_transactions()
    print(list_of_smart_contracts)

    #lets make sure it didn't create a refund transaction for the initial sender.
    print(chain.get_vm().state.account_db.has_receivable_transactions(GENESIS_PRIVATE_KEY.public_key.to_canonical_address()))

    # print('ASDASD')
    # print(chain.chaindb.get_receipts(imported_block.header, Receipt)[0].logs[0].data)

    #
    # Interacting with deployed smart contract step 1) add send transaction
    #
    chain = MainnetChain(testdb, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    simple_token = w3.eth.contract(
        address=Web3.toChecksumAddress(deployed_contract_address),
        abi=contract_interface['abi'],
    )

    w3_tx2 = simple_token.functions.totalSupply().buildTransaction(W3_TX_DEFAULTS)


    chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=max_gas,
        to=deployed_contract_address,
        value=0,
        data=decode_hex(w3_tx2['data']),
        v=0,
        r=0,
        s=0
    )

    #lets make sure it subtracts the entire max gas
    initial_balance = chain.get_vm().state.account_db.get_balance(GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    chain.import_current_queue_block()
    final_balance = chain.get_vm().state.account_db.get_balance(GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    assert((initial_balance - final_balance) == max_gas)

    #
    # Interacting with deployed smart contract step 2) add receive transaction to smart contract chain
    #

    chain = MainnetChain(testdb, deployed_contract_address, private_keys[0])
    chain.populate_queue_block_with_receive_tx()
    imported_block = chain.import_current_queue_block()


    #now lets look at the reciept to see the result
    assert(to_int(chain.chaindb.get_receipts(imported_block.header, Receipt)[0].logs[0].data) == EXPECTED_TOTAL_SUPPLY)
    print("Total supply call gave expected result!")
    gas_used = to_int(chain.chaindb.get_receipts(imported_block.header, Receipt)[0].gas_used)


    #
    # Interacting with deployed smart contract step 3) Receiving refund of extra gas that wasn't used in the computation
    #
    initial_balance = chain.get_vm().state.account_db.get_balance(GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    chain = MainnetChain(testdb, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)
    chain.populate_queue_block_with_receive_tx()
    imported_block = chain.import_current_queue_block()
    final_balance = chain.get_vm().state.account_db.get_balance(GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    assert ((final_balance - initial_balance) == (max_gas - gas_used))
    print("Refunded gas is the expected amount.")


def test_keystore_load_save():
    import eth_keyfile
    file_location = ''
    json_data = eth_keyfile.load_keyfile(file_location)

    print(json_data)

    private_key = encode_hex(eth_keyfile.extract_key_from_keyfile(file_location, '123456789'))

    print(private_key)

# test_keystore_load_save()
# sys.exit()

def save_dev_test_keystore_files():
    import eth_keyfile
    from hvm.constants import random_private_keys
    from pathlib import Path
    import json

    basepath = Path('keystore')

    for i in range(len(random_private_keys)):
        path = basepath / Path('instance_'+str(i))
        private_key = random_private_keys[i]

        json_keyfile = eth_keyfile.create_keyfile_json(private_key, b'dev')

        with path.open('w') as file:
            file.write(json.dumps(json_keyfile))


# save_dev_test_keystore_files()
# sys.exit()

def test_upnp():
    import upnpclient

    from upnpclient.upnp import Device

    # device = Device('http://192.168.1.9:5000/ssdp/desc-DSM-eth0.xml')
    #
    # print(device)

    devices = upnpclient.discover()

    print(devices)

test_upnp()
sys.exit()



