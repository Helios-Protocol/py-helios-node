import logging
import os
import random
import time
import sys
from pprint import pprint

import eth_keyfile
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
    to_wei,
    to_checksum_address)
from helios.dev_tools import create_dev_test_random_blockchain_database, \
    create_dev_test_blockchain_database_with_given_transactions, create_new_genesis_params_and_state, \
    create_predefined_blockchain_database
from eth_keys import keys
from sys import exit

from hvm.vm.forks import PhotonVM
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
    compile_and_get_contract_interface)
SIMPLE_TOKEN_SOLIDITY_SRC_FILE = 'contract_data/erc20.sol'


from rlp_cython.sedes.big_endian_int import BigEndianInt

def call_on_chain(testdb, from_address, chain_address, data, code_address = b'', convert_to_int = True):
    smart_contract_chain = TestnetTesterChain(testdb, chain_address, TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())
    tx_nonce = smart_contract_chain.get_vm().state.account_db.get_nonce(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    max_gas = 20000000
    transaction = smart_contract_chain.create_transaction(
        gas_price=1,
        gas=max_gas,
        to=chain_address,
        value=0,
        nonce=tx_nonce,
        data=data,
        code_address=code_address,
        v=0,
        r=0,
        s=0
    )

    spoof_transaction = SpoofTransaction(transaction, from_=from_address)

    result = smart_contract_chain.get_transaction_result(spoof_transaction)

    if convert_to_int:
        return to_int(result)
    else:
        return result


def test_initial_deploy_min_and_re_mint_tokens():
    testdb = MemoryDB()
    create_predefined_blockchain_database(testdb)

    # deploy the contract
    deployed_contract_address, contract_interface = deploy_contract(testdb, 'helios_delegated_token.sol', 'HeliosDelegatedToken', TESTNET_GENESIS_PRIVATE_KEY)

    w3 = Web3()
    max_gas = 20000000



    #
    # The deploy address should have received a new transaction to mint tokens. Import it.
    #
    chain = TestnetTesterChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())
    chain.populate_queue_block_with_receive_tx()
    block = chain.import_current_queue_block()
    chain.get_transaction_by_hash(block.receive_transactions[0].send_transaction_hash)

    #
    # Check to make sure the balance on the sender chain is equal to the total supply
    #

    HeliosDelegatedToken = w3.hls.contract(
        address=Web3.toChecksumAddress(deployed_contract_address),
        abi=contract_interface['abi']
    )

    # getting total supply from the smart contract chain
    w3_tx = HeliosDelegatedToken.functions.totalSupply().buildTransaction(W3_TX_DEFAULTS)

    total_supply = call_on_chain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), deployed_contract_address, decode_hex(w3_tx['data']))

    # getting balance on sender chain
    w3_tx = HeliosDelegatedToken.functions.getBalance().buildTransaction(W3_TX_DEFAULTS)

    balance = call_on_chain(testdb,
                            TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                            TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                            decode_hex(w3_tx['data']),
                            deployed_contract_address)

    assert(total_supply == balance)

    #
    # try to mint some tokens by sending mintTokens from a chain that isnt the smart contract chain
    #
    receiver_2_chain = TestnetTesterChain(testdb, RECEIVER2.public_key.to_canonical_address(), RECEIVER2, PhotonVM.with_zero_min_time_between_blocks())

    w3_tx = HeliosDelegatedToken.functions.mintTokens(10000).buildTransaction(W3_TX_DEFAULTS)

    receiver_2_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
        value=0,
        data=decode_hex(w3_tx['data']),
        code_address=deployed_contract_address,
    )
    receiver_2_chain.import_current_queue_block()

    chain.populate_queue_block_with_receive_tx()
    chain.import_current_queue_block()

    #
    # Make sure the balance is still total_supply
    #

    # getting balance on sender chain
    w3_tx = HeliosDelegatedToken.functions.getBalance().buildTransaction(W3_TX_DEFAULTS)

    balance = call_on_chain(testdb,
                            TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                            TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                            decode_hex(w3_tx['data']),
                            deployed_contract_address)

    assert (total_supply == balance)


#test_initial_deploy_min_and_re_mint_tokens()


def test_valid_transfer():
    testdb = MemoryDB()
    create_predefined_blockchain_database(testdb)

    # deploy the contract
    deployed_contract_address, contract_interface = deploy_contract(testdb, 'helios_delegated_token.sol',
                                                                    'HeliosDelegatedToken', TESTNET_GENESIS_PRIVATE_KEY)

    w3 = Web3()
    max_gas = 20000000
    send_amount = 10000

    #
    # The deploy address should have received a new transaction to mint tokens. Import it.
    #
    chain = TestnetTesterChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                               TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())
    chain.populate_queue_block_with_receive_tx()
    block = chain.import_current_queue_block()
    chain.get_transaction_by_hash(block.receive_transactions[0].send_transaction_hash)

    #
    # Send tokens with execute on send
    #
    HeliosDelegatedToken = w3.hls.contract(
        address=Web3.toChecksumAddress(deployed_contract_address),
        abi=contract_interface['abi']
    )

    w3_tx = HeliosDelegatedToken.functions.transfer(send_amount).buildTransaction(W3_TX_DEFAULTS)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=RECEIVER2.public_key.to_canonical_address(),
        value=0,
        data=decode_hex(w3_tx['data']),
        code_address=deployed_contract_address,
        execute_on_send=True,
    )
    chain.import_current_queue_block()

    #
    # Receive tokens
    #
    receiver_2_chain = TestnetTesterChain(testdb, RECEIVER2.public_key.to_canonical_address(), RECEIVER2,
                                          PhotonVM.with_zero_min_time_between_blocks())
    receiver_2_chain.populate_queue_block_with_receive_tx()
    receiver_2_chain.import_current_queue_block()

    #
    # Make sure there is a refund to sender
    #
    receivable_transactions = chain.create_receivable_transactions()
    print(receivable_transactions)


    # #
    # # Check sender balance
    # #
    #
    # # getting total supply from the smart contract chain
    # w3_tx = HeliosDelegatedToken.functions.totalSupply().buildTransaction(W3_TX_DEFAULTS)
    #
    # total_supply = call_on_chain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
    #                              deployed_contract_address, decode_hex(w3_tx['data']))
    #
    # # getting balance on sender chain
    # w3_tx = HeliosDelegatedToken.functions.getBalance().buildTransaction(W3_TX_DEFAULTS)
    #
    # balance = call_on_chain(testdb,
    #                         TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
    #                         TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
    #                         decode_hex(w3_tx['data']),
    #                         deployed_contract_address)
    #
    # assert (balance == total_supply - send_amount)
    #
    # #
    # # Check receiver balance
    # #
    #
    # balance = call_on_chain(testdb,
    #                         RECEIVER2.public_key.to_canonical_address(),
    #                         RECEIVER2.public_key.to_canonical_address(),
    #                         decode_hex(w3_tx['data']),
    #                         deployed_contract_address)
    #
    # assert (balance == send_amount)




test_valid_transfer()


def test_invalid_transfers():
    testdb = MemoryDB()
    create_predefined_blockchain_database(testdb)

    # deploy the contract
    deployed_contract_address, contract_interface = deploy_contract(testdb, 'helios_delegated_token.sol', 'HeliosDelegatedToken', TESTNET_GENESIS_PRIVATE_KEY)

    w3 = Web3()
    max_gas = 20000000
    send_amount = 10000

    #
    # The deploy address should have received a new transaction to mint tokens. Import it.
    #
    chain = TestnetTesterChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())
    chain.populate_queue_block_with_receive_tx()
    block = chain.import_current_queue_block()
    chain.get_transaction_by_hash(block.receive_transactions[0].send_transaction_hash)

    #
    # Send tokens without execute on send. Nothing should happen
    #
    HeliosDelegatedToken = w3.hls.contract(
        address=Web3.toChecksumAddress(deployed_contract_address),
        abi=contract_interface['abi']
    )

    w3_tx = HeliosDelegatedToken.functions.transfer(send_amount).buildTransaction(W3_TX_DEFAULTS)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=RECEIVER2.public_key.to_canonical_address(),
        value=0,
        data=decode_hex(w3_tx['data']),
        code_address=deployed_contract_address,
    )
    chain.import_current_queue_block()


    #
    # Receive tokens
    #
    receiver_2_chain = TestnetTesterChain(testdb, RECEIVER2.public_key.to_canonical_address(), RECEIVER2, PhotonVM.with_zero_min_time_between_blocks())
    receiver_2_chain.populate_queue_block_with_receive_tx()
    receiver_2_chain.import_current_queue_block()

    #
    # Check sender balance
    #

    # getting total supply from the smart contract chain
    w3_tx = HeliosDelegatedToken.functions.totalSupply().buildTransaction(W3_TX_DEFAULTS)

    total_supply = call_on_chain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), deployed_contract_address, decode_hex(w3_tx['data']))

    # getting balance on sender chain
    w3_tx = HeliosDelegatedToken.functions.getBalance().buildTransaction(W3_TX_DEFAULTS)

    balance = call_on_chain(testdb,
                            TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                            TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                            decode_hex(w3_tx['data']),
                            deployed_contract_address)


    assert (balance == total_supply)

    #
    # Check receiver balance
    #

    balance = call_on_chain(testdb,
                            RECEIVER2.public_key.to_canonical_address(),
                            RECEIVER2.public_key.to_canonical_address(),
                            decode_hex(w3_tx['data']),
                            deployed_contract_address)
    assert (balance == 0)

    #
    # Try to send more than the balance. receiver2's balance is 0
    #

    w3_tx = HeliosDelegatedToken.functions.transfer(send_amount).buildTransaction(W3_TX_DEFAULTS)

    receiver_2_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
        value=0,
        data=decode_hex(w3_tx['data']),
        code_address=deployed_contract_address,
        execute_on_send = True,
    )
    receiver_2_chain.import_current_queue_block()


    # getting balance on sender chain
    w3_tx = HeliosDelegatedToken.functions.getBalance().buildTransaction(W3_TX_DEFAULTS)

    balance = call_on_chain(testdb,
                            TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                            TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                            decode_hex(w3_tx['data']),
                            deployed_contract_address)

    assert (balance == total_supply)

    #
    # Check receiver balance
    #

    balance = call_on_chain(testdb,
                            RECEIVER2.public_key.to_canonical_address(),
                            RECEIVER2.public_key.to_canonical_address(),
                            decode_hex(w3_tx['data']),
                            deployed_contract_address)
    assert (balance == 0)

#test_invalid_transfers()


def test_hypothesis_database():
    testdb = LevelDB('/home/tommy/hypothesis_database/full')

    max_gas = 20000000
    send_amount = 10000

    chain = TestnetTesterChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY, PhotonVM.with_zero_min_time_between_blocks())

    contract_interface = compile_and_get_contract_interface('helios_delegated_token.sol', 'HeliosDelegatedToken')
    deployed_contract_address = decode_hex('0x3256033babc1febe99340de5d8092592ccf4321c')
    w3 = Web3()

    HeliosDelegatedToken = w3.hls.contract(
        address=Web3.toChecksumAddress(deployed_contract_address),
        abi=contract_interface['abi']
    )

    # getting total supply from the smart contract chain
    w3_tx = HeliosDelegatedToken.functions.totalSupply().buildTransaction(W3_TX_DEFAULTS)

    total_supply = call_on_chain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), deployed_contract_address, decode_hex(w3_tx['data']))

    print("total_supply")
    print(total_supply)
    # getting balance on sender chain
    w3_tx = HeliosDelegatedToken.functions.getBalance().buildTransaction(W3_TX_DEFAULTS)

    balance = call_on_chain(testdb,
                            decode_hex('0xaD6872B6f67aCAA3148C0Ccc49E7c4dE48B0becA'),
                            decode_hex('0xaD6872B6f67aCAA3148C0Ccc49E7c4dE48B0becA'),
                            decode_hex(w3_tx['data']),
                            deployed_contract_address)

    print('balance')
    print(balance)

    absolute_keystore_path = '/d:/Google Drive/forex/blockchain_coding/Helios/prototype_laptop/helios-code-examples/web3_py/deploy_token/test_keystore.txt'  # path to your keystore file
    keystore_password = 'LVTxfhwY4PvUEK8h'  # your keystore password
    private_key = keys.PrivateKey(eth_keyfile.extract_key_from_keyfile(absolute_keystore_path, keystore_password))

    # Create a new account to send it to
    new_account = w3.hls.account.create()
    new_private_key = new_account._key_obj

    amount_to_transfer = 1000

    w3_tx1 = HeliosDelegatedToken.functions.transfer(amount_to_transfer).buildTransaction(W3_TX_DEFAULTS)
    
    deployed_chain = TestnetTesterChain(testdb, private_key.public_key.to_canonical_address(), private_key, PhotonVM.with_zero_min_time_between_blocks())

    deployed_chain.create_and_sign_transaction_for_queue_block(
        gas_price=1,
        gas=max_gas,
        to=new_private_key.public_key.to_canonical_address(),
        value=0,
        data=decode_hex(w3_tx['data']),
        code_address=deployed_contract_address,
        execute_on_send=True,
    )
    
    transaction = {
        'to': new_private_key.public_key.to_canonical_address(),
        'gas': 20000000,  # make sure this is enough to cover deployment
        'value': 0,
        'chainId': 42,
        'data': w3_tx1['data'],
        'codeAddress': deployed_contract_address,  # The code address tells it where the smart contract code is.
    }
    
    

#test_hypothesis_database()