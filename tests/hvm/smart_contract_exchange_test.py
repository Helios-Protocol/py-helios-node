import logging
import os
import random
import time
import sys
from pprint import pprint
from hvm.db.read_only import ReadOnlyDB

from hvm import constants
from hvm import TestnetChain
from hvm.chains.testnet import (
    TESTNET_GENESIS_PARAMS,
    TESTNET_GENESIS_STATE,
    TESTNET_GENESIS_PRIVATE_KEY,
    TESTNET_NETWORK_ID,
    TestnetTesterChain)

from hvm.utils.spoof import (
    SpoofTransaction,
)

from hvm.types import Timestamp
from eth_abi import (
    decode_abi,
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
    to_wei
)
from helios.dev_tools import create_dev_test_random_blockchain_database, \
    create_dev_test_blockchain_database_with_given_transactions, create_new_genesis_params_and_state, \
    create_predefined_blockchain_database
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

from eth_typing import Hash32
from eth_keys.datatypes import(
        BaseKey,
        PublicKey,
        PrivateKey
)

# import matplotlib.pyplot as plt

from hvm.utils.profile import profile

from helios.dev_tools import create_dev_fixed_blockchain_database

from hvm.rlp.receipts import (
    Receipt,
)
from solc import compile_source, compile_files, link_code, get_solc_version

from eth_utils import to_int

from hvm.utils.address import generate_contract_address

from pathlib import Path

import pickle

from helios_web3 import HeliosWeb3 as Web3

from hvm.vm.forks import PhotonVM
from tests.integration_test_helpers import W3_TX_DEFAULTS

from hvm.constants import CREATE_CONTRACT_ADDRESS, ZERO_ADDRESS, GAS_TX

#for testing purposes we will just have the primary private key hardcoded
#TODO: save to encrypted json file
#primary_private_keys = [b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5', b'\xa41\x95@\xbb\xa5\xde\xbbc\xffR\x8a\x18\x06\x95\xa3\xd7\xd2\x95]5{\x12\xe4n\xb6R\xd7S\x96\xf0+', b'\xd8>Fh\xefT\x04jf\x13\xca|E\xc4\x91\xed\x07\xcd\x02fW\xd8s;\xd8\xe4\xde\xb9\xbc\xe4\xf0I', b'\x83\x1d\xf6\xaf-\x00\xbfS4\x0f\xcds\x18"\xdd\x906]e\xfc\xe6\x0c?\xb1v20\xced7y\xf4', b")M\xf4\x1c\xb7\xe0Z\xf4\x17F\x9b\x089'\x004\xd3\x89\xd8\x80\xf5`\xa2\x11\x00\x90\xbd\x0f&KjZ", b'RI\xda\xbc7\xc4\xe8\tz\xfaI\x1f\xa1\x02{v\x0e\xac\x87W\xa2s\x81L4M\xad\xbd\xb3\x84\xaae', b'>kG\xd5\xb3qG\x84\xa6"\x1c~\xb6\xbf\x96\xac\n\x88\xfb\x05\x8aG\r\xe9Z\x16\x15\xb1P\xe0\xb7[', b'\x87\xf6\xb1\xa7v\x8bv<\xa3\xe5\xb18\xa7u\x99\xbaBa\xe9\xd5\x0e\xcb\x0f?\x84nZ\xba\xdf\xa3\x8a~', b'`$g\xe9\xa5r\xd2\xacG&\xf81^\x98\xf7\xda\xa5\xf4\x93)\xf3\x0c\x18\x84\xe4)!\x9dR\xa0\xac\xd3', b'\xcfd\xd5|\xe2\xf1\xda\xb9\x1f|\xb9\xdc\xeb \xd7\xb0\x81g\xdc\x03\xd6dQ\xf14\x19`\x94o\xf7\xc7\x1b', b'}LO\x14($d\n!\x1a\x91\xa8S\xb3\x05\xaa\x89\xf2\x0b\x97\xd3\x1c#\xe7\x86g`\xf1\x1a\xedXW']
from hvm.constants import random_private_keys
from hvm.vm.forks.helios_testnet.blocks import HeliosMicroBlock, HeliosTestnetBlock

def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(random_private_keys[instance_number])

private_keys = []
for i in range(10):
    private_keys.append(get_primary_node_private_helios_key(i))

from helios.utils.logging import (
    setup_helios_stderr_logging,
)

log_level = getattr(logging, 'DEBUG')
log_level = 1 #trace
logger, _, handler_stream = setup_helios_stderr_logging(log_level)
logger.propagate = True

logger = logging.getLogger('hp2p')
logger.setLevel(log_level)
logger.addHandler(handler_stream)

logger = logging.getLogger('hvm')
logger.setLevel(log_level)
logger.addHandler(handler_stream)

SENDER = TESTNET_GENESIS_PRIVATE_KEY
RECEIVER = get_primary_node_private_helios_key(1)
RECEIVER2 = get_primary_node_private_helios_key(2)
RECEIVER3 = get_primary_node_private_helios_key(3)
RECEIVER4 = get_primary_node_private_helios_key(4)

from tests.hvm.smart_contract_helpers import (
    compile_sol_and_save_to_file,
    load_compiled_sol_dict,
    import_all_pending_smart_contract_blocks,
    format_receipt_for_web3_to_extract_events,
    deploy_contract,
    compile_and_get_contract_interface, call_on_chain)


def test_exchange_get_token_balance_static_call():
    testdb = MemoryDB()
    create_predefined_blockchain_database(testdb)

    # deploy the token
    token_contract_address, token_contract_interface = deploy_contract(testdb, 'helios_delegated_token.sol', 'HeliosDelegatedToken', TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())

    # deploy the exchange
    exchange_contract_address, exchange_contract_interface = deploy_contract(testdb, 'decentralized_exchange.sol', 'DecentralizedExchange', TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())

    w3 = Web3()
    max_gas = 20000000
    send_amount = 1000

    #
    # Receive total supply
    #
    chain = TestnetTesterChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())
    chain.populate_queue_block_with_receive_tx()
    chain.import_current_queue_block()


    #
    # Send tokens to exchange smart contract
    #
    HeliosDelegatedToken = w3.hls.contract(
        address=Web3.toChecksumAddress(token_contract_address),
        abi=token_contract_interface['abi']
    )

    w3_tx = HeliosDelegatedToken.functions.transfer(send_amount).buildTransaction(W3_TX_DEFAULTS)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=0,
        data=decode_hex(w3_tx['data']),
        code_address=token_contract_address,
        execute_on_send=True,
    )
    chain.import_current_queue_block()

    #
    # Receive tokens at the exchange
    #
    exchange_chain = TestnetTesterChain(testdb, exchange_contract_address, TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())
    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()

    #
    # Use staticcall on exchange to get the token balance on its own chain
    #

    DecentralizedExchange = w3.hls.contract(
        address=Web3.toChecksumAddress(exchange_contract_address),
        abi=exchange_contract_interface['abi']
    )

    # getting total supply from the smart contract chain
    w3_tx = DecentralizedExchange.functions.getTokenBalance(token_contract_address).buildTransaction(W3_TX_DEFAULTS)

    token_balance = call_on_chain(testdb, exchange_contract_address, exchange_contract_address, decode_hex(w3_tx['data']))

    print(token_balance)

    #
    # Use delegatecall on exchange to get teh token balance on its own chain
    #

    # getting total supply from the smart contract chain
    w3_tx = DecentralizedExchange.functions.getTokenBalanceDelegate(token_contract_address).buildTransaction(W3_TX_DEFAULTS)

    token_balance = call_on_chain(testdb, exchange_contract_address, exchange_contract_address, decode_hex(w3_tx['data']))

    print(token_balance)



#test_exchange_get_token_balance_static_call()


def test_exchange_deposit_and_withdraw_tokens():
    testdb = MemoryDB()
    create_predefined_blockchain_database(testdb)

    # deploy the token
    token_contract_address, token_contract_interface = deploy_contract(testdb, 'helios_delegated_token.sol', 'HeliosDelegatedToken', TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())

    # deploy the exchange
    exchange_contract_address, exchange_contract_interface = deploy_contract(testdb, 'decentralized_exchange.sol', 'DecentralizedExchange', TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())

    w3 = Web3()
    max_gas = 20000000
    send_amount = 1000
    withdraw_amount = 100

    #
    # Receive total supply
    #
    chain = TestnetTesterChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())
    chain.populate_queue_block_with_receive_tx()
    chain.import_current_queue_block()


    #
    # Call the deposit function on the exchange to deposit some tokens
    #
    DecentralizedExchange = w3.hls.contract(
        address=Web3.toChecksumAddress(exchange_contract_address),
        abi=exchange_contract_interface['abi']
    )

    w3_tx = DecentralizedExchange.functions.depositTokens(exchange_contract_address, token_contract_address, send_amount, 0).buildTransaction(W3_TX_DEFAULTS)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=0,
        data=decode_hex(w3_tx['data']),
        execute_on_send=True,
    )
    block = chain.import_current_queue_block()


    #
    # Receive the transactions on the smart contract
    #
    exchange_chain = TestnetTesterChain(testdb, exchange_contract_address, TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())
    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()



    #
    # Check the token balance on the exchange
    #
    w3_tx = DecentralizedExchange.functions.getTokenBalance(token_contract_address).buildTransaction(W3_TX_DEFAULTS)

    token_balance_stored_in_token_storage = call_on_chain(testdb, exchange_contract_address, exchange_contract_address, decode_hex(w3_tx['data']))

    print('token_balance_stored_in_token_storage')
    print(token_balance_stored_in_token_storage)
    assert(token_balance_stored_in_token_storage == send_amount)


    #
    # Check the sender token balance on the exchange
    #
    w3_tx = DecentralizedExchange.functions.tokens(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), token_contract_address).buildTransaction(W3_TX_DEFAULTS)

    token_balance_stored_in_exchange_storage = call_on_chain(testdb, exchange_contract_address, exchange_contract_address, decode_hex(w3_tx['data']))

    print('token_balance_stored_in_exchange_storage')
    print(token_balance_stored_in_exchange_storage)
    assert(token_balance_stored_in_exchange_storage == 0)


    #
    # Process pending deposits
    #
    w3_tx = DecentralizedExchange.functions.processPendingDeposits(
        TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
        token_contract_address
    ).buildTransaction(W3_TX_DEFAULTS)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=0,
        data=decode_hex(w3_tx['data']),
    )
    chain.import_current_queue_block()

    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()


    #
    # Check the sender token balance on the exchange
    #
    w3_tx = DecentralizedExchange.functions.tokens(
        TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
        token_contract_address
    ).buildTransaction(W3_TX_DEFAULTS)

    token_balance_stored_in_exchange_storage = call_on_chain(testdb, exchange_contract_address, exchange_contract_address, decode_hex(w3_tx['data']))
    print('token_balance_stored_in_exchange_storage')
    print(token_balance_stored_in_exchange_storage)
    assert(token_balance_stored_in_exchange_storage == send_amount)

    #
    # Withdraw the tokens
    #
    w3_tx = DecentralizedExchange.functions.withdrawTokens(
        token_contract_address,
        withdraw_amount
    ).buildTransaction(W3_TX_DEFAULTS)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=0,
        data=decode_hex(w3_tx['data']),
    )
    chain.import_current_queue_block()

    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()

    chain.populate_queue_block_with_receive_tx()
    chain.import_current_queue_block()
    
    
    #
    # Check the sender token balance on the exchange
    #
    w3_tx = DecentralizedExchange.functions.tokens(
        TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
        token_contract_address
    ).buildTransaction(W3_TX_DEFAULTS)

    token_balance_stored_in_exchange_storage = call_on_chain(testdb, exchange_contract_address, exchange_contract_address, decode_hex(w3_tx['data']))
    print('token_balance_stored_in_exchange_storage')
    print(token_balance_stored_in_exchange_storage)
    assert(token_balance_stored_in_exchange_storage == send_amount-withdraw_amount)


    #
    # Check the sender token balance on the their own chain
    #
    HeliosDelegatedToken = w3.hls.contract(
        address=Web3.toChecksumAddress(token_contract_address),
        abi=token_contract_interface['abi']
    )
    w3_tx = HeliosDelegatedToken.functions.getBalance().buildTransaction(W3_TX_DEFAULTS)

    token_balance_stored_in_sender_chain = call_on_chain(testdb,
                                                         TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                                                         TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                                                         decode_hex(w3_tx['data']),
                                                         code_address=token_contract_address,)
    print('token_balance_stored_in_sender_chain')
    print(token_balance_stored_in_sender_chain)
    assert(token_balance_stored_in_sender_chain == to_wei(300000000, 'ether')-(send_amount-withdraw_amount))

    



#test_exchange_deposit_and_withdraw_tokens()


def test_exchange_deposit_and_withdraw_HLS():
    testdb = MemoryDB()
    create_predefined_blockchain_database(testdb)

    # deploy the exchange
    exchange_contract_address, exchange_contract_interface = deploy_contract(testdb, 'decentralized_exchange.sol', 'DecentralizedExchange', TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())

    w3 = Web3()
    max_gas = 20000000
    deposit_amount_1 = 1000
    deposit_amount_2 = 500
    withdraw_amount = 100

    chain = TestnetTesterChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())

    #
    # Deposit some HLS using the depositHLS function
    #
    DecentralizedExchange = w3.hls.contract(
        address=Web3.toChecksumAddress(exchange_contract_address),
        abi=exchange_contract_interface['abi']
    )

    w3_tx = DecentralizedExchange.functions.depositHLS().buildTransaction(W3_TX_DEFAULTS)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=deposit_amount_1,
        data=decode_hex(w3_tx['data']),
    )
    chain.import_current_queue_block()
    
    exchange_chain = TestnetTesterChain(testdb, exchange_contract_address, TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())
    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()


    
    
    #
    # Check the sender HLS balance on the exchange
    #
    w3_tx = DecentralizedExchange.functions.tokens(
        TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
        ZERO_ADDRESS
    ).buildTransaction(W3_TX_DEFAULTS)

    HLS_balance_stored_in_exchange_storage = call_on_chain(testdb, exchange_contract_address, exchange_contract_address, decode_hex(w3_tx['data']))
    print('HLS_balance_stored_in_exchange_storage')
    print(HLS_balance_stored_in_exchange_storage)
    assert(HLS_balance_stored_in_exchange_storage == deposit_amount_1)
    
    #
    # Deposit some HLS by just paying the contract chain
    #
    chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=deposit_amount_2,
    )
    chain.import_current_queue_block()
    
    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()
    
    
    #
    # Check the sender HLS balance on the exchange
    #
    w3_tx = DecentralizedExchange.functions.tokens(
        TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
        ZERO_ADDRESS
    ).buildTransaction(W3_TX_DEFAULTS)

    HLS_balance_stored_in_exchange_storage = call_on_chain(testdb, exchange_contract_address, exchange_contract_address, decode_hex(w3_tx['data']))
    print('HLS_balance_stored_in_exchange_storage')
    print(HLS_balance_stored_in_exchange_storage)
    assert(HLS_balance_stored_in_exchange_storage == deposit_amount_1+deposit_amount_2)

    
    #
    # Withdraw some HLS
    #
    w3_tx = DecentralizedExchange.functions.withdrawHLS(withdraw_amount).buildTransaction(W3_TX_DEFAULTS)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=0,
        data=decode_hex(w3_tx['data']),
    )
    chain.import_current_queue_block()

    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()

    chain.populate_queue_block_with_receive_tx()
    chain.import_current_queue_block()

    
    #
    # Check the sender HLS balance on the exchange
    #
    w3_tx = DecentralizedExchange.functions.tokens(
        TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
        ZERO_ADDRESS
    ).buildTransaction(W3_TX_DEFAULTS)

    HLS_balance_stored_in_exchange_storage = call_on_chain(testdb, exchange_contract_address, exchange_contract_address, decode_hex(w3_tx['data']))
    print('HLS_balance_stored_in_exchange_storage')
    print(HLS_balance_stored_in_exchange_storage)
    assert(HLS_balance_stored_in_exchange_storage == deposit_amount_1+deposit_amount_2-withdraw_amount)
    
#test_exchange_deposit_and_withdraw_HLS()

def test_exchange_order_book():
    testdb = MemoryDB()
    create_predefined_blockchain_database(testdb)
    
    # deploy the token
    token_contract_address, token_contract_interface = deploy_contract(testdb, 'helios_delegated_token.sol', 'HeliosDelegatedToken', TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())

    # deploy the exchange
    exchange_contract_address, exchange_contract_interface = deploy_contract(testdb, 'decentralized_exchange.sol', 'DecentralizedExchange', TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())

    w3 = Web3()
    max_gas = 20000000
    order_1_amount = 100
    order_1_price = to_wei(0.0002, 'ether')
    order_2_amount = 200
    order_2_price = to_wei(0.0001, 'ether')
    order_3_amount = 1000
    order_3_price = to_wei(0.00005, 'ether')

    chain = TestnetTesterChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())

    #
    # Add order
    #
    DecentralizedExchange = w3.hls.contract(
        address=Web3.toChecksumAddress(exchange_contract_address),
        abi=exchange_contract_interface['abi']
    )

    w3_tx = DecentralizedExchange.functions.addOrder(token_contract_address, ZERO_ADDRESS, order_1_amount, order_1_price).buildTransaction(W3_TX_DEFAULTS)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=0,
        data=decode_hex(w3_tx['data']),
    )
    chain.import_current_queue_block()
    
    exchange_chain = TestnetTesterChain(testdb, exchange_contract_address, TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())
    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()
    
    #
    # Add order
    #
  
    w3_tx = DecentralizedExchange.functions.addOrder(token_contract_address, ZERO_ADDRESS, order_2_amount, order_2_price).buildTransaction(W3_TX_DEFAULTS)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=0,
        data=decode_hex(w3_tx['data']),
    )
    chain.import_current_queue_block()
    
    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()
    
    #
    # Add order
    #

    w3_tx = DecentralizedExchange.functions.addOrder(token_contract_address, ZERO_ADDRESS, order_3_amount, order_3_price).buildTransaction(W3_TX_DEFAULTS)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=0,
        data=decode_hex(w3_tx['data']),
    )
    chain.import_current_queue_block()
    
    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()
    
    #
    # Get the order book
    #
    w3_tx = DecentralizedExchange.functions.getOrderBookWeb3(
        token_contract_address, ZERO_ADDRESS
    ).buildTransaction(W3_TX_DEFAULTS)

    order_book = call_on_chain(testdb, exchange_contract_address, exchange_contract_address, decode_hex(w3_tx['data']), convert_to_int = False)
    print('order_book')

    order_book_decoded = decode_abi(('uint256[2][100]',), order_book)
    print(order_book)
    assert(order_book_decoded[:3] == (100, 200000000000000), (200, 100000000000000), (1000, 50000000000000))

# test_exchange_order_book()

def test_exchange_trade():
    testdb = MemoryDB()
    create_predefined_blockchain_database(testdb)
    
    # deploy the token
    token_contract_address, token_contract_interface = deploy_contract(testdb, 'helios_delegated_token.sol', 'HeliosDelegatedToken', TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())

    # deploy the exchange
    exchange_contract_address, exchange_contract_interface = deploy_contract(testdb, 'decentralized_exchange.sol', 'DecentralizedExchange', TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())

    w3 = Web3()
    max_gas = 20000000
    token_deposit_amount = to_wei(100000, 'ether')
    hls_deposit_amount = to_wei(1000, 'ether')

    # Selling HLS for tokens
    order_1_amount = to_wei(100, 'ether')
    order_1_price = to_wei(1000, 'ether') # buy 1000 tokens/HLS
    order_2_amount = to_wei(2, 'ether')
    order_2_price = to_wei(700, 'ether')  # buy 700 tokens/HLS
    order_3_amount = to_wei(1, 'ether')
    order_3_price = to_wei(500, 'ether')  # buy 500 tokens/HLS
    order_4_amount = to_wei(1000, 'ether')
    order_4_price = to_wei(500, 'ether')  # buy 500 tokens/HLS

    # Selling tokens for HLS
    order_5_amount = to_wei(1400, 'ether')
    order_5_price = to_wei(0.00142857142, 'ether')  # buy 0.00142857142 HLS/token (800 tokens/hls)

    # Selling tokens for HLS
    order_6_amount = to_wei(8000, 'ether')
    order_6_price = to_wei(0.00142857142, 'ether')  # buy 0.00142857142 HLS/token (800 tokens/hls)

    #
    # Receive total supply
    #
    chain = TestnetTesterChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())
    chain.populate_queue_block_with_receive_tx()
    chain.import_current_queue_block()


    #
    # Deposit some tokens
    #
    DecentralizedExchange = w3.hls.contract(
        address=Web3.toChecksumAddress(exchange_contract_address),
        abi=exchange_contract_interface['abi']
    )

    w3_tx = DecentralizedExchange.functions.depositTokens(exchange_contract_address, token_contract_address, token_deposit_amount, 0).buildTransaction(W3_TX_DEFAULTS)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=0,
        data=decode_hex(w3_tx['data']),
        execute_on_send=True,
    )
    chain.import_current_queue_block()

    exchange_chain = TestnetTesterChain(testdb, exchange_contract_address, TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())
    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()
    
    w3_tx = DecentralizedExchange.functions.processPendingDeposits(
        TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
        token_contract_address
    ).buildTransaction(W3_TX_DEFAULTS)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=0,
        data=decode_hex(w3_tx['data']),
    )
    chain.import_current_queue_block()

    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()


    #
    # Deposit some HLS
    #
    w3_tx = DecentralizedExchange.functions.depositHLS().buildTransaction(W3_TX_DEFAULTS)
    receiver_chain = TestnetTesterChain(testdb, RECEIVER.public_key.to_canonical_address(),RECEIVER, PhotonVM.with_zero_min_time_between_blocks())

    receiver_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=hls_deposit_amount,
        data=decode_hex(w3_tx['data']),
    )
    receiver_chain.import_current_queue_block()

    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()
    
    #
    # Place 3 orders to buy some tokens with your HLS
    #
    #function trade(address sell_token, address buy_token, uint256 amount, uint256 price)
    w3_tx = DecentralizedExchange.functions.trade(
        ZERO_ADDRESS,
        token_contract_address,
        order_1_amount,
        order_1_price).buildTransaction(W3_TX_DEFAULTS)

    receiver_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=0,
        data=decode_hex(w3_tx['data']),
    )
    receiver_chain.import_current_queue_block()
    
    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()
    
    #
    # Place 3 orders to buy some tokens with your HLS
    #
    #function trade(address sell_token, address buy_token, uint256 amount, uint256 price)
    w3_tx = DecentralizedExchange.functions.trade(
        ZERO_ADDRESS,
        token_contract_address,
        order_2_amount,
        order_2_price).buildTransaction(W3_TX_DEFAULTS)

    receiver_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=0,
        data=decode_hex(w3_tx['data']),
    )
    receiver_chain.import_current_queue_block()
    
    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()
    
    #
    # Place 3 orders to buy some tokens with your HLS
    #
    #function trade(address sell_token, address buy_token, uint256 amount, uint256 price)
    w3_tx = DecentralizedExchange.functions.trade(
        ZERO_ADDRESS,
        token_contract_address,
        order_3_amount,
        order_3_price).buildTransaction(W3_TX_DEFAULTS)

    receiver_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=0,
        data=decode_hex(w3_tx['data']),
    )
    receiver_chain.import_current_queue_block()
    
    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()
    
    #
    # Place 4th order that will fail
    #
    #function trade(address sell_token, address buy_token, uint256 amount, uint256 price)
    w3_tx = DecentralizedExchange.functions.trade(
        ZERO_ADDRESS,
        token_contract_address,
        order_4_amount,
        order_4_price).buildTransaction(W3_TX_DEFAULTS)

    receiver_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=0,
        data=decode_hex(w3_tx['data']),
    )
    receiver_chain.import_current_queue_block()
    
    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()
    
    #
    # Get amount in orders
    #
    #b'\r\x160\xcbw\xc0\r\x95\xf7\xfa2\xbc\xcf\xe8\x00Cc\x96\x81\xbe

    w3_tx = DecentralizedExchange.functions.getAmountInOrders(
        RECEIVER.public_key.to_canonical_address(),
        ZERO_ADDRESS
    ).buildTransaction(W3_TX_DEFAULTS)

    amount_in_orders = call_on_chain(testdb, exchange_contract_address, exchange_contract_address, decode_hex(w3_tx['data']))
    print('amount_in_orders')
    print(amount_in_orders)
    assert(amount_in_orders == order_1_amount + order_2_amount + order_3_amount)

    
    #
    # Get the order book
    #
    w3_tx = DecentralizedExchange.functions.getOrderBookWeb3(
        ZERO_ADDRESS, token_contract_address
    ).buildTransaction(W3_TX_DEFAULTS)

    order_book = call_on_chain(testdb, exchange_contract_address, exchange_contract_address, decode_hex(w3_tx['data']), convert_to_int = False)
    print('order_book')

    order_book_decoded = decode_abi(('uint256[2][100]',), order_book)
    print(order_book_decoded)
    
    #
    # Place order to buy that will use part of first order
    #
    #function trade(address sell_token, address buy_token, uint256 amount, uint256 price)
    w3_tx = DecentralizedExchange.functions.trade(
        token_contract_address,
        ZERO_ADDRESS,
        order_5_amount,
        order_5_price).buildTransaction(W3_TX_DEFAULTS)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=0,
        data=decode_hex(w3_tx['data']),
    )
    chain.import_current_queue_block()

    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()
    
    #
    # Place order to buy that will use part of first order
    #
    #function trade(address sell_token, address buy_token, uint256 amount, uint256 price)
    w3_tx = DecentralizedExchange.functions.trade(
        token_contract_address,
        ZERO_ADDRESS,
        order_6_amount,
        order_6_price).buildTransaction(W3_TX_DEFAULTS)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=exchange_contract_address,
        value=0,
        data=decode_hex(w3_tx['data']),
    )

    chain.import_current_queue_block()


    exchange_chain.populate_queue_block_with_receive_tx()
    exchange_chain.import_current_queue_block()


    #
    # Get the order book
    #
    w3_tx = DecentralizedExchange.functions.getOrderBookWeb3(
         token_contract_address,ZERO_ADDRESS
    ).buildTransaction(W3_TX_DEFAULTS)

    order_book = call_on_chain(testdb, exchange_contract_address, exchange_contract_address, decode_hex(w3_tx['data']), convert_to_int = False)
    print('order_book')

    order_book_decoded = decode_abi(('uint256[2][100]',), order_book)
    print(order_book_decoded)
    #
    # #
    # # Get the inverse price
    # #
    # w3_tx = DecentralizedExchange.functions.getInversePrice(
    #     #to_wei(0.00125, 'ether')
    #     1
    # ).buildTransaction(W3_TX_DEFAULTS)
    #
    # inverse_price = call_on_chain(testdb, exchange_contract_address, exchange_contract_address, decode_hex(w3_tx['data']), convert_to_int = False)
    # print('inverse_price')
    # print(to_int(inverse_price))
    #
    #
    # Check the sender token balance on the exchange
    #
    w3_tx = DecentralizedExchange.functions.tokens(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), ZERO_ADDRESS).buildTransaction(W3_TX_DEFAULTS)

    token_balance_stored_in_exchange_storage = call_on_chain(testdb, exchange_contract_address, exchange_contract_address, decode_hex(w3_tx['data']))

    print('token_balance_stored_in_exchange_storage')
    print(token_balance_stored_in_exchange_storage)



test_exchange_trade()