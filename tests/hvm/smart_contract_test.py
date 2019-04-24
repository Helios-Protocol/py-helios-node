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


from eth_utils import (
    encode_hex,
    decode_hex,        
)
from helios.dev_tools import create_dev_test_random_blockchain_database, create_dev_test_blockchain_database_with_given_transactions
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

# import matplotlib.pyplot as plt

from hvm.utils.profile import profile

#for testing purposes we will just have the primary private key hardcoded
#TODO: save to encrypted json file
#primary_private_keys = [b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5', b'\xa41\x95@\xbb\xa5\xde\xbbc\xffR\x8a\x18\x06\x95\xa3\xd7\xd2\x95]5{\x12\xe4n\xb6R\xd7S\x96\xf0+', b'\xd8>Fh\xefT\x04jf\x13\xca|E\xc4\x91\xed\x07\xcd\x02fW\xd8s;\xd8\xe4\xde\xb9\xbc\xe4\xf0I', b'\x83\x1d\xf6\xaf-\x00\xbfS4\x0f\xcds\x18"\xdd\x906]e\xfc\xe6\x0c?\xb1v20\xced7y\xf4', b")M\xf4\x1c\xb7\xe0Z\xf4\x17F\x9b\x089'\x004\xd3\x89\xd8\x80\xf5`\xa2\x11\x00\x90\xbd\x0f&KjZ", b'RI\xda\xbc7\xc4\xe8\tz\xfaI\x1f\xa1\x02{v\x0e\xac\x87W\xa2s\x81L4M\xad\xbd\xb3\x84\xaae', b'>kG\xd5\xb3qG\x84\xa6"\x1c~\xb6\xbf\x96\xac\n\x88\xfb\x05\x8aG\r\xe9Z\x16\x15\xb1P\xe0\xb7[', b'\x87\xf6\xb1\xa7v\x8bv<\xa3\xe5\xb18\xa7u\x99\xbaBa\xe9\xd5\x0e\xcb\x0f?\x84nZ\xba\xdf\xa3\x8a~', b'`$g\xe9\xa5r\xd2\xacG&\xf81^\x98\xf7\xda\xa5\xf4\x93)\xf3\x0c\x18\x84\xe4)!\x9dR\xa0\xac\xd3', b'\xcfd\xd5|\xe2\xf1\xda\xb9\x1f|\xb9\xdc\xeb \xd7\xb0\x81g\xdc\x03\xd6dQ\xf14\x19`\x94o\xf7\xc7\x1b', b'}LO\x14($d\n!\x1a\x91\xa8S\xb3\x05\xaa\x89\xf2\x0b\x97\xd3\x1c#\xe7\x86g`\xf1\x1a\xedXW']
from hvm.constants import random_private_keys
from hvm.vm.forks.helios_testnet.blocks import HeliosMicroBlock, HeliosTestnetBlock

def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(random_private_keys[instance_number])

SENDER = GENESIS_PRIVATE_KEY
RECEIVER = get_primary_node_private_helios_key(1)
RECEIVER2 = get_primary_node_private_helios_key(2)
RECEIVER3 = get_primary_node_private_helios_key(3)
RECEIVER4 = get_primary_node_private_helios_key(4)


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


    W3_TX_DEFAULTS = {'gas': 0, 'gasPrice': 0, 'chainId': 0}

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

    #compiled_sol = compile_files([SOLIDITY_SRC_FILE])

    from contract_data.compiled_contract import compiled_sol

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

    #contractAddress

    print("Used the correct amount of gas.")

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

test_smart_contract_deploy_system()