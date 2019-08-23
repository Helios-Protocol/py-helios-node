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
)

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
home = str(Path.home())

os.environ["SOLC_BINARY"] = home + "/.py-solc/solc-v0.4.25/bin/solc"

try:
    get_solc_version()
except Exception:
    print("Solc not found. Installing")
    from solc import install_solc
    install_solc('v0.4.25')

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
logger, _, handler_stream = setup_helios_stderr_logging(log_level)
logger.propagate = True

logger = logging.getLogger('hp2p')
logger.setLevel(logging.DEBUG)
logger.addHandler(handler_stream)

logger = logging.getLogger('hvm')
logger.setLevel(logging.DEBUG)
logger.addHandler(handler_stream)

SENDER = TESTNET_GENESIS_PRIVATE_KEY
RECEIVER = get_primary_node_private_helios_key(1)
RECEIVER2 = get_primary_node_private_helios_key(2)
RECEIVER3 = get_primary_node_private_helios_key(3)
RECEIVER4 = get_primary_node_private_helios_key(4)

from tests.integration_test_helpers import (
    compile_sol_and_save_to_file,
    load_compiled_sol_dict
)
SIMPLE_TOKEN_SOLIDITY_SRC_FILE = 'contract_data/erc20.sol'

# compile_sol_and_save_to_file('contract_data/erc20.sol', 'contract_data/erc20_compiled.pkl')
# exit()
# compiled_sol = load_compiled_sol_dict('contract_data/airdrop_compiled.pkl')
#
# print(compiled_sol.keys())
# exit()
from rlp_cython.sedes.big_endian_int import BigEndianInt

def format_receipt_for_web3_to_extract_events(receipt, tx_hash, chain):
    def hex_to_32_bit_int_bytes(hex_val):
        sede = BigEndianInt(32)
        return sede.serialize(to_int(hexstr = hex_val))

    from helios.rpc.format import receipt_to_dict
    receipt_dict = receipt_to_dict(receipt, tx_hash, chain)
    for i in range(len(receipt_dict['logs'])):
        receipt_dict['logs'][i]['data'] = decode_hex(receipt_dict['logs'][i]['data'])

        receipt_dict['logs'][i]['topics'] = list(map(hex_to_32_bit_int_bytes, receipt_dict['logs'][i]['topics']))
    return receipt_dict

def import_all_pending_smart_contract_blocks(database):
    chain = TestnetChain(database, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                         TESTNET_GENESIS_PRIVATE_KEY)

    # now we need to add the block to the smart contract
    list_of_smart_contracts = chain.get_vm().state.account_db.get_smart_contracts_with_pending_transactions()
    for airdrop_contract_address in list_of_smart_contracts:
        chain = TestnetChain(database, airdrop_contract_address, private_keys[0])

        chain.populate_queue_block_with_receive_tx()
        imported_block = chain.import_current_queue_block()
    return list_of_smart_contracts

def test_erc_20_smart_contract_deploy_system():

    #absolute_dir = os.path.dirname(os.path.realpath(__file__))
    #testdb = LevelDB(absolute_dir + "/predefined_databases/simple_token")
    
    # testdb = JournalDB(testdb)
    testdb = MemoryDB()
    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    coin_mature_time = chain.get_vm(timestamp = Timestamp(int(time.time()))).consensus_db.coin_mature_time_for_staking

    now = int(time.time())
    key_balance_dict = {
        private_keys[0]: (1000000000000, now - coin_mature_time * 10 - 100)


    }
    create_dev_fixed_blockchain_database(testdb, key_balance_dict)

    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    min_time_between_blocks = chain.get_vm(timestamp = Timestamp(int(time.time()))).min_time_between_blocks
    for private_key, balance_time in key_balance_dict.items():
        assert(chain.get_vm().state.account_db.get_balance(private_key.public_key.to_canonical_address()) == balance_time[0])


    EXPECTED_TOTAL_SUPPLY = 10000000000000000000000

    #compiled_sol = compile_files([SIMPLE_TOKEN_SOLIDITY_SRC_FILE])

    compiled_sol = load_compiled_sol_dict('contract_data/erc20_compiled.pkl')

    contract_interface = compiled_sol['{}:SimpleToken'.format(SIMPLE_TOKEN_SOLIDITY_SRC_FILE)]

    w3 = Web3()

    SimpleToken = w3.hls.contract(
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

    initial_balance = chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    imported_block = chain.import_current_queue_block()
    final_balance = chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    gas_used = to_int(chain.chaindb.get_receipts(imported_block.header, Receipt)[0].gas_used)
    assert ((initial_balance - final_balance) == gas_used)

    print(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    print(generate_contract_address(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), imported_block.transactions[0].nonce))
    print(chain.chaindb.get_receipts(imported_block.header, Receipt)[0].logs[0].address)

    #contractAddress

    print("Used the correct amount of gas.")

    list_of_smart_contracts = import_all_pending_smart_contract_blocks(testdb)
    deployed_contract_address = list_of_smart_contracts[0]

    list_of_smart_contracts = chain.get_vm().state.account_db.get_smart_contracts_with_pending_transactions()
    print(list_of_smart_contracts)

    #lets make sure it didn't create a refund transaction for the initial sender.
    print(chain.get_vm().state.account_db.has_receivable_transactions(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address()))

    # print('ASDASD')
    # print(chain.chaindb.get_receipts(imported_block.header, Receipt)[0].logs[0].data)

    #
    # Interacting with deployed smart contract step 1) add send transaction
    #
    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    simple_token = w3.hls.contract(
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
    initial_balance = chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    print("waiting {} seconds before importing next block".format(min_time_between_blocks))
    time.sleep(min_time_between_blocks)
    chain.import_current_queue_block()
    final_balance = chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    assert((initial_balance - final_balance) == max_gas)

    #
    # Interacting with deployed smart contract step 2) add receive transaction to smart contract chain
    #

    chain = TestnetChain(testdb, deployed_contract_address, private_keys[0])
    chain.populate_queue_block_with_receive_tx()

    receivable_transactions = chain.get_vm().state.account_db.get_receivable_transactions(deployed_contract_address)
    print('receivable_transactions before imported into contract chain')
    print(receivable_transactions)

    print("waiting {} seconds before importing next block".format(min_time_between_blocks))
    time.sleep(min_time_between_blocks)
    imported_block = chain.import_current_queue_block()

    receipt = chain.chaindb.get_receipts(imported_block.header, Receipt)[0]
    receipt_dict = format_receipt_for_web3_to_extract_events(receipt, imported_block.receive_transactions[0].hash, chain)

    rich_logs = simple_token.events.Print().processReceipt(receipt_dict)
    print(rich_logs[0]['args'])
    print('a')

    #now lets look at the reciept to see the result
    assert(to_int(chain.chaindb.get_receipts(imported_block.header, Receipt)[0].logs[0].data) == EXPECTED_TOTAL_SUPPLY)
    print("Total supply call gave expected result!")
    gas_used = to_int(chain.chaindb.get_receipts(imported_block.header, Receipt)[0].gas_used)



    #
    # Interacting with deployed smart contract step 3) Receiving refund of extra gas that wasn't used in the computation
    #
    initial_balance = chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    #
    # Make sure the receive transaction is no longer in the account receivable
    #
    receivable_transactions = chain.get_vm().state.account_db.get_receivable_transactions(deployed_contract_address)
    print('receivable_transactions after imported into contract chain')
    print(receivable_transactions)

    chain.populate_queue_block_with_receive_tx()

    print("waiting {} seconds before importing next block".format(min_time_between_blocks))
    time.sleep(min_time_between_blocks)
    imported_block = chain.import_current_queue_block()
    final_balance = chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    assert ((final_balance - initial_balance) == (max_gas - gas_used))
    print("Refunded gas is the expected amount.")





# test_erc_20_smart_contract_deploy_system()
# exit()

def test_erc_20_smart_contract_call():
    from hvm.utils.spoof import (
        SpoofTransaction,
    )

    absolute_dir = os.path.dirname(os.path.realpath(__file__))
    testdb = LevelDB(absolute_dir + "/predefined_databases/simple_token")
    
    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    EXPECTED_TOTAL_SUPPLY = 10000000000000000000000
    deployed_contract_address = b'%\xf1\xf7[(2\xd5l\xe4DL\x97\xbf+\xe2M[pN\xdc'
    max_gas = 20000000
    transaction_sender = TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address()


    compiled_sol = load_compiled_sol_dict('contract_data/erc20_compiled.pkl')

    contract_interface = compiled_sol['{}:SimpleToken'.format(SIMPLE_TOKEN_SOLIDITY_SRC_FILE)]

    w3 = Web3()
    simple_token = w3.hls.contract(
        address=Web3.toChecksumAddress(deployed_contract_address),
        abi=contract_interface['abi'],
    )

    w3_tx2 = simple_token.functions.totalSupply().buildTransaction(W3_TX_DEFAULTS)

    tx_nonce = chain.get_vm().state.account_db.get_nonce(transaction_sender)

    transaction = chain.create_transaction(
        gas_price=0x01,
        gas=max_gas,
        to=deployed_contract_address,
        value=0,
        nonce=tx_nonce,
        data=decode_hex(w3_tx2['data']),
        v=0,
        r=0,
        s=0
    )

    spoof_transaction = SpoofTransaction(transaction, from_=transaction_sender)

    result = chain.get_transaction_result(spoof_transaction)

    assert(big_endian_to_int(result) == EXPECTED_TOTAL_SUPPLY)

    #
    # Make sure # TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address() has the total supply of tokens
    #

    w3_tx2 = simple_token.functions.balanceOf(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address()).buildTransaction(W3_TX_DEFAULTS)

    tx_nonce = chain.get_vm().state.account_db.get_nonce(transaction_sender)

    transaction = chain.create_transaction(
        gas_price=0x01,
        gas=max_gas,
        to=deployed_contract_address,
        value=0,
        nonce=tx_nonce,
        data=decode_hex(w3_tx2['data']),
        v=0,
        r=0,
        s=0
    )

    spoof_transaction = SpoofTransaction(transaction, from_=transaction_sender)

    result = chain.get_transaction_result(spoof_transaction)

    assert(big_endian_to_int(result) == EXPECTED_TOTAL_SUPPLY)

    #
    # Make sure other addresses have no balance
    #

    w3_tx2 = simple_token.functions.balanceOf(private_keys[5].public_key.to_canonical_address()).buildTransaction(W3_TX_DEFAULTS)

    tx_nonce = chain.get_vm().state.account_db.get_nonce(transaction_sender)

    transaction = chain.create_transaction(
        gas_price=0x01,
        gas=max_gas,
        to=deployed_contract_address,
        value=0,
        nonce=tx_nonce,
        data=decode_hex(w3_tx2['data']),
        v=0,
        r=0,
        s=0
    )

    spoof_transaction = SpoofTransaction(transaction, from_=transaction_sender)

    result = chain.get_transaction_result(spoof_transaction)

    assert (big_endian_to_int(result) == 0)


# test_erc_20_smart_contract_call()
# exit()


def test_airdrop_simple_token_contract_call():


    simple_token_contract_address = b'%\xf1\xf7[(2\xd5l\xe4DL\x97\xbf+\xe2M[pN\xdc'

    absolute_dir = os.path.dirname(os.path.realpath(__file__))
    testdb = LevelDB(absolute_dir + "/predefined_databases/simple_token")
    testdb = ReadOnlyDB(testdb)

    max_gas = 20000000

    #
    # airdrop contract deploy
    #
    compiled_airdrop_sol = load_compiled_sol_dict('contract_data/airdrop_compiled.pkl')

    EXPECTED_TOTAL_SUPPLY = 10000000000000000000000

    airdrop_contract_interface = compiled_airdrop_sol['contract_data/airdrop.sol:Airdrop']

    w3 = Web3()

    airdrop = w3.hls.contract(
        abi=airdrop_contract_interface['abi'],
        bytecode=airdrop_contract_interface['bin']
    )

    # Build transaction to deploy the contract
    w3_airdrop_tx = airdrop.constructor().buildTransaction(W3_TX_DEFAULTS)

    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                         TESTNET_GENESIS_PRIVATE_KEY)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=max_gas,
        to=CREATE_CONTRACT_ADDRESS,
        value=0,
        data=decode_hex(w3_airdrop_tx['data']),
        v=0,
        r=0,
        s=0
    )

    print("deploying airdrop smart contract")
    chain.import_current_queue_block()

    list_of_smart_contracts = import_all_pending_smart_contract_blocks(testdb)
    airdrop_contract_address = list_of_smart_contracts[0]


    #
    # Now send tokens to the airdrop contract address
    #
    # TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address() has the total supply of tokens

    balance_for_airdrop_contract = 100000000000000

    simple_token_compiled_sol = load_compiled_sol_dict('contract_data/erc20_compiled.pkl')

    simple_token_contract_interface = simple_token_compiled_sol['{}:SimpleToken'.format(SIMPLE_TOKEN_SOLIDITY_SRC_FILE)]

    simple_token = w3.hls.contract(
        address=Web3.toChecksumAddress(simple_token_contract_address),
        abi=simple_token_contract_interface['abi'],
    )

    # Build transaction to deploy the contract
    w3_send_tx = simple_token.functions.transfer(
        airdrop_contract_address,
        balance_for_airdrop_contract
    ).buildTransaction(W3_TX_DEFAULTS)

    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                         TESTNET_GENESIS_PRIVATE_KEY)

    min_time_between_blocks = chain.get_vm(timestamp=Timestamp(int(time.time()))).min_time_between_blocks

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=max_gas,
        to=simple_token_contract_address,
        value=0,
        data=decode_hex(w3_send_tx['data']),
        v=0,
        r=0,
        s=0
    )

    print("waiting {} seconds before importing next block".format(min_time_between_blocks))
    time.sleep(min_time_between_blocks)

    print("sending tokens to smart contract address")
    chain.import_current_queue_block()

    import_all_pending_smart_contract_blocks(testdb)


    #
    # Make sure the airdrop contract has the correct balance
    #

    print("now checking balance")

    w3_balance_tx = simple_token.functions.balanceOf(airdrop_contract_address).buildTransaction(W3_TX_DEFAULTS)

    tx_nonce = chain.get_vm().state.account_db.get_nonce(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    transaction = chain.create_transaction(
        gas_price=0x01,
        gas=max_gas,
        to=simple_token_contract_address,
        value=0,
        nonce=tx_nonce,
        data=decode_hex(w3_balance_tx['data']),
        v=0,
        r=0,
        s=0
    )

    spoof_transaction = SpoofTransaction(transaction, from_=TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    result = chain.get_transaction_result(spoof_transaction)

    assert(big_endian_to_int(result) == balance_for_airdrop_contract)

    #
    # Tell the airdrop smart contract to call the other contract.
    #

    print("waiting {} seconds before importing next block".format(min_time_between_blocks))
    time.sleep(min_time_between_blocks)

    w3_tx_params = W3_TX_DEFAULTS
    w3_tx_params['to'] = airdrop_contract_address

    # Build transaction to deploy the contract
    w3_airdrop_tx = airdrop.functions.drop(
        simple_token_contract_address,
        [private_keys[1].public_key.to_canonical_address()],
        [1000]
    ).buildTransaction(w3_tx_params)

    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                         TESTNET_GENESIS_PRIVATE_KEY)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=max_gas,
        to=airdrop_contract_address,
        value=0,
        data=decode_hex(w3_airdrop_tx['data']),
        v=0,
        r=0,
        s=0
    )

    print("Sending out airdrop")
    chain.import_current_queue_block()

    import_all_pending_smart_contract_blocks(testdb)






# test_airdrop_simple_token_contract_call()
# exit()

def test_talamus_contract():
    absolute_dir = os.path.dirname(os.path.realpath(__file__))
    testdb = LevelDB(absolute_dir + "/predefined_databases/talamus_test")

    testdb = ReadOnlyDB(testdb)
    talamus_contract_address = decode_hex('0x81bdf63b9a6e871f560dca1d55e8732b5ccdc2f9')

    print(private_keys[0].public_key.to_checksum_address())
    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    min_time_between_blocks = chain.get_vm(timestamp=Timestamp(int(time.time()))).min_time_between_blocks

    COMPILED_SOLIDITY_FILE = load_compiled_sol_dict('contract_data/talamus_compiled.pkl')
    SOLIDITY_SRC_FILE = 'contract/talamus.sol'

    contract_interface = COMPILED_SOLIDITY_FILE['{}:TalamusHealth'.format(SOLIDITY_SRC_FILE)]

    w3 = Web3()

    talamus_contract = w3.hls.contract(
        abi=contract_interface['abi'],
        bytecode=contract_interface['bin']
    )

    max_gas = 2000000
    w3_tx_params = {
        'gas': max_gas,
        'gasPrice': to_wei(2, 'gwei'),
        'chainId': 2,
        'to': talamus_contract_address,
        'value': 0,
        'nonce': 1
    }

    # from rpc
    # {'gasPrice': 2000000000, 'chainId': 2, 'gas': 2000000, 'to': b'\x81\xbd\xf6;\x9an\x87\x1fV\r\xca\x1dU\xe8s+\\\xcd\xc2\xf9', 'value': 0, 'data': '0x010f836e0000000000000000000000000000000000000000000000000000000000000000', 'nonce': 1}
    # us
    # {'gas': 2000000, 'gasPrice': 2000000000, 'chainId': 2, 'to': b'\x81\xbd\xf6;\x9an\x87\x1fV\r\xca\x1dU\xe8s+\\\xcd\xc2\xf9', 'value': 0, 'data': '0x010f836e0000000000000000000000000000000000000000000000000000000000000000'}

    hash_to_save = Hash32(32 * b'\x00')

    w3_tx = talamus_contract.functions.saveHash(hash_to_save).buildTransaction(w3_tx_params)

    print(w3_tx)

    # tx = chain.create_and_sign_transaction_for_queue_block(
    #     gas_price=w3_tx['gasPrice'],
    #     gas=w3_tx['gas'],
    #     to=w3_tx['to'],
    #     value=w3_tx['value'],
    #     data=decode_hex(w3_tx['data']),
    #     nonce=1,
    #     v=0,
    #     r=0,
    #     s=0
    # )

    tx = chain.create_and_sign_transaction_for_queue_block(
        gas_price=w3_tx['gasPrice'],
        gas=w3_tx['gas'],
        to=w3_tx['to'],
        value=w3_tx['value'],
        data=b'0x010f836e0000000000000000000000000000000000000000000000000000000000000000',
        nonce=1,
        v=0,
        r=0,
        s=0
    )

    print('ZZZZZZZZZZZZZZZZZZZZZZZZZZZ')
    print(tx.as_dict())

    # from rpc
    # {'nonce': 1, 'gas_price': 2000000000, 'gas': 2000000, 'to': b'\x81\xbd\xf6;\x9an\x87\x1fV\r\xca\x1dU\xe8s+\\\xcd\xc2\xf9', 'value': 0, 'data': b'0x010f836e0000000000000000000000000000000000000000000000000000000000000000', 'v': 38, 'r': 77546672203976404837758472880488256719656950035867254665717724200250517648493, 's': 2580236846734574215375389852957773325366136635134534812926657997746477469836}
    # from us
    # {'nonce': 1, 'gas_price': 2000000000, 'gas': 2000000, 'to': b'\x81\xbd\xf6;\x9an\x87\x1fV\r\xca\x1dU\xe8s+\\\xcd\xc2\xf9', 'value': 0, 'data': b'\x01\x0f\x83n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 'v': 39, 'r': 39349908228946674104603389597151977495442914775500474614266302539829498168651, 's': 23552581665426625568029915589486661695498739587988697017071052606525926751079}

    chain.import_current_queue_block()

    contract_chain = TestnetChain(ReadOnlyDB(testdb), talamus_contract_address, private_keys[0])

    receivable_transactions = contract_chain.get_vm().state.account_db.get_receivable_transactions(talamus_contract_address)
    print('receivable_transactions before imported into contract chain')
    print(receivable_transactions)

    contract_chain.populate_queue_block_with_receive_tx()
    contract_block = contract_chain.import_current_queue_block()



    contract_chain = TestnetChain(testdb, talamus_contract_address, private_keys[0])
    contract_chain.import_block(contract_block)

    contract_chain = TestnetChain(testdb, talamus_contract_address, private_keys[0])

    receivable_transactions = contract_chain.get_vm().state.account_db.get_receivable_transactions(talamus_contract_address)
    print('receivable_transactions after imported into contract chain')
    print(receivable_transactions)



# test_talamus_contract()
# exit()


def test_talamus_contract_2():
    absolute_dir = os.path.dirname(os.path.realpath(__file__))
    testdb = LevelDB(absolute_dir + "/predefined_databases/talamus_test_save_hash")

    testdb = ReadOnlyDB(testdb)
    talamus_contract_address = decode_hex('0x81bdf63b9a6e871f560dca1d55e8732b5ccdc2f9')

    chain = TestnetChain(testdb, private_keys[0].public_key.to_canonical_address(), private_keys[0])

    receivable_transactions = chain.get_vm().state.account_db.get_receivable_transactions(talamus_contract_address)
    print('receivable_transactions before imported into contract chain')
    print(receivable_transactions)


# test_talamus_contract_2()
# exit()




def _test_airdrop_calling_erc_20():

    # testdb = LevelDB('/home/tommy/.local/share/helios/instance_test/mainnet/chain/full/')
    # testdb = JournalDB(testdb)
    testdb = MemoryDB()
    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    coin_mature_time = chain.get_vm(timestamp = Timestamp(int(time.time()))).consensus_db.coin_mature_time_for_staking

    genesis_params, genesis_state = create_new_genesis_params_and_state(TESTNET_GENESIS_PRIVATE_KEY, 1000000 * 10 ** 18, int(time.time()) - coin_mature_time * 10000)

    # import genesis block
    chain = TestnetChain.from_genesis(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), genesis_params, genesis_state, TESTNET_GENESIS_PRIVATE_KEY)


    #
    # erc20 contract deploy
    #

    compiled_erc20_sol = load_compiled_sol_dict('contract_data/erc20_compiled.pkl')

    EXPECTED_TOTAL_SUPPLY = 10000000000000000000000

    erc20_contract_interface = compiled_erc20_sol['contract_data/erc20.sol:SimpleToken']

    w3 = Web3()

    SimpleToken = w3.hls.contract(
        abi=erc20_contract_interface['abi'],
        bytecode=erc20_contract_interface['bin']
    )

    # Build transaction to deploy the contract
    w3_erc20_tx = SimpleToken.constructor().buildTransaction(W3_TX_DEFAULTS)

    max_gas = 20000000

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=max_gas,
        to=CREATE_CONTRACT_ADDRESS,
        value=0,
        data=decode_hex(w3_erc20_tx['data']),
        v=0,
        r=0,
        s=0
    )

    #time.sleep(1)
    print("deploying erc20 smart contract")
    imported_block = chain.import_current_queue_block()

    #now we need to add the block to the smart contract
    list_of_smart_contracts = chain.get_vm().state.account_db.get_smart_contracts_with_pending_transactions()
    erc20_contract_address = list_of_smart_contracts[0]

    chain = TestnetChain(testdb, erc20_contract_address, private_keys[0])

    chain.populate_queue_block_with_receive_tx()
    imported_block = chain.import_current_queue_block()


    #
    # airdrop contract deploy
    #
    compiled_airdrop_sol = load_compiled_sol_dict('contract_data/airdrop_compiled.pkl')

    EXPECTED_TOTAL_SUPPLY = 10000000000000000000000

    airdrop_contract_interface = compiled_airdrop_sol['contract_data/airdrop.sol:Airdrop']

    Airdrop = w3.hls.contract(
        abi=airdrop_contract_interface['abi'],
        bytecode=airdrop_contract_interface['bin']
    )

    # Build transaction to deploy the contract
    w3_airdrop_tx = Airdrop.constructor().buildTransaction(W3_TX_DEFAULTS)

    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=max_gas,
        to=CREATE_CONTRACT_ADDRESS,
        value=0,
        data=decode_hex(w3_airdrop_tx['data']),
        v=0,
        r=0,
        s=0
    )

    print("deploying airdrop smart contract")
    imported_block = chain.import_current_queue_block()

    # now we need to add the block to the smart contract
    list_of_smart_contracts = chain.get_vm().state.account_db.get_smart_contracts_with_pending_transactions()
    airdrop_contract_address = list_of_smart_contracts[0]

    chain = TestnetChain(testdb, airdrop_contract_address, private_keys[0])

    chain.populate_queue_block_with_receive_tx()
    imported_block = chain.import_current_queue_block()




    #
    # Interacting with deployed smart contract step 1) add send transaction
    #
    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    print(erc20_contract_interface['abi'])
    simple_token = w3.hls.contract(
        address=Web3.toChecksumAddress(erc20_contract_address),
        abi=erc20_contract_interface['abi'],
    )

    airdrop_token_balance = 1000

    w3_erc20_send = simple_token.functions.transfer(Web3.toChecksumAddress(airdrop_contract_address), airdrop_token_balance).buildTransaction(W3_TX_DEFAULTS)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=max_gas,
        to=erc20_contract_address,
        value=0,
        data=decode_hex(w3_erc20_send['data']),
        v=0,
        r=0,
        s=0
    )
    imported_block = chain.import_current_queue_block()

    chain = TestnetChain(testdb, erc20_contract_address, private_keys[0])
    chain.populate_queue_block_with_receive_tx()
    imported_block = chain.import_current_queue_block()

    from pprint import pprint
    receipt = chain.chaindb.get_receipts(imported_block.header, Receipt)[0]

    receipt_dict = format_receipt_for_web3_to_extract_events(receipt, imported_block.receive_transactions[0].hash, chain)

    rich_logs = simple_token.events.Transfer().processReceipt(receipt_dict)
    print(rich_logs)
    print(rich_logs[0]['args'])
    print('a')

    assert(to_int(chain.chaindb.get_receipts(imported_block.header, Receipt)[0].logs[0].data) == airdrop_token_balance)

    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    w3_erc20_balance = simple_token.functions.balanceOf(Web3.toChecksumAddress(airdrop_contract_address)).buildTransaction(W3_TX_DEFAULTS)

    chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=max_gas,
        to=erc20_contract_address,
        value=0,
        data=decode_hex(w3_erc20_balance['data']),
        v=0,
        r=0,
        s=0
    )
    imported_block = chain.import_current_queue_block()

    chain = TestnetChain(testdb, erc20_contract_address, private_keys[0])
    chain.populate_queue_block_with_receive_tx()
    imported_block = chain.import_current_queue_block()

    print(chain.chaindb.get_receipts(imported_block.header, Receipt)[0].logs)


    exit()
    #now lets look at the reciept to see the result
    assert(to_int(chain.chaindb.get_receipts(imported_block.header, Receipt)[0].logs[0].data) == EXPECTED_TOTAL_SUPPLY)
    print("Total supply call gave expected result!")
    gas_used = to_int(chain.chaindb.get_receipts(imported_block.header, Receipt)[0].gas_used)


    #
    # Interacting with deployed smart contract step 3) Receiving refund of extra gas that wasn't used in the computation
    #
    initial_balance = chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    chain.populate_queue_block_with_receive_tx()
    imported_block = chain.import_current_queue_block()
    final_balance = chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    assert ((final_balance - initial_balance) == (max_gas - gas_used))
    print("Refunded gas is the expected amount.")

# test_airdrop_calling_erc_20()

HELIOS_DELEGATED_TOKEN_SOLIDITY_SRC_FILE = 'contract_data/helios_delegated_token.sol'

def test_helios_delegated_token():
    
    compile_sol_and_save_to_file(HELIOS_DELEGATED_TOKEN_SOLIDITY_SRC_FILE, 'contract_data/helios_delegated_token.pkl')
    compiled_sol = load_compiled_sol_dict('contract_data/helios_delegated_token.pkl')

    contract_interface = compiled_sol['{}:HeliosDelegatedToken'.format(HELIOS_DELEGATED_TOKEN_SOLIDITY_SRC_FILE)]
    
    # deploy the contract
    w3 = Web3()

    HeliosDelegatedToken = w3.hls.contract(
        abi=contract_interface['abi'],
        bytecode=contract_interface['bin']
    )

    # Build transaction to deploy the contract
    w3_tx1 = HeliosDelegatedToken.constructor().buildTransaction(W3_TX_DEFAULTS)

    max_gas = 20000000

    testdb = MemoryDB()
    create_predefined_blockchain_database(testdb)

    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
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

    # time.sleep(1)
    print("deploying smart contract")

    chain.import_current_queue_block()

    list_of_smart_contracts = import_all_pending_smart_contract_blocks(testdb)
    deployed_contract_address = list_of_smart_contracts[0]

    print(encode_hex(deployed_contract_address))
    
    #
    # Now call it to see what this says
    #
    HeliosDelegatedToken = w3.hls.contract(
        address=Web3.toChecksumAddress(deployed_contract_address),
        abi=contract_interface['abi']
    )

    w3_tx2 = HeliosDelegatedToken.functions.getCoinbase().buildTransaction(W3_TX_DEFAULTS)

    tx_sender = TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address()

    tx_nonce = chain.get_vm().state.account_db.get_nonce(tx_sender)

    transaction = chain.create_transaction(
        gas_price=0x01,
        gas=max_gas,
        to=deployed_contract_address,
        value=0,
        nonce=tx_nonce,
        data=decode_hex(w3_tx2['data']),
        v=0,
        r=0,
        s=0
    )

    spoof_transaction = SpoofTransaction(transaction, from_=tx_sender)
    print("tx sender: {}".format(encode_hex(tx_sender)))
    result = chain.get_transaction_result(spoof_transaction)
    print("Result from 'this': {}".format(encode_hex(result)))

test_helios_delegated_token()
exit()