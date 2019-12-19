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

from hvm.constants import CREATE_CONTRACT_ADDRESS


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


def test_exchange_deposit():
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


    #
    # Check the sender token balance on the exchange
    #
    w3_tx = DecentralizedExchange.functions.tokens(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), token_contract_address).buildTransaction(W3_TX_DEFAULTS)

    token_balance_stored_in_exchange_storage = call_on_chain(testdb, exchange_contract_address, exchange_contract_address, decode_hex(w3_tx['data']))

    print('token_balance_stored_in_exchange_storage')
    print(token_balance_stored_in_exchange_storage)


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

    start_time = time.time()
    token_balance_stored_in_exchange_storage = call_on_chain(testdb, exchange_contract_address, exchange_contract_address, decode_hex(w3_tx['data']))
    end_time = time.time()
    print("Took {} seconds".format(end_time-start_time))
    print('token_balance_stored_in_exchange_storage')
    print(token_balance_stored_in_exchange_storage)




test_exchange_deposit()