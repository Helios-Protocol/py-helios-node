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

from hvm.constants import GAS_CALLSTIPEND, GAS_TX

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
    compile_and_get_contract_interface,
    assemble,
)

import pytest

from eth_utils import (
    decode_hex,
    encode_hex,
    hexstr_if_str,
    int_to_big_endian,
    to_bytes,
    to_canonical_address,
)
from hvm import (
    constants
)
from hvm.constants import ZERO_HASH32, ZERO_ADDRESS, BLOCK_GAS_LIMIT, GAS_CALLSTIPEND, CREATE_CONTRACT_ADDRESS
from hvm.utils.address import (
    force_bytes_to_address,
    generate_contract_address, generate_safe_contract_address)
from hvm.db.atomic import (
    AtomicDB
)
from hvm.db.chain import (
    ChainDB
)
from hvm.exceptions import (
    InvalidInstruction,
    VMError,
    ValidationError,
    ForbiddenOperationForSurrogateCall, OutOfGas, ForbiddenOperationForExecutingOnSend)
from hvm.rlp.headers import (
    BlockHeader,
)
from hvm.utils.padding import (
    pad32
)
from hvm.vm import (
    opcode_values
)
from hvm.vm.forks import (
    PhotonVM
)
from hvm.vm.message import (
    Message,
)

from hvm.constants import CREATE_CONTRACT_ADDRESS


@pytest.mark.parametrize(
    'call_data, call_value, call_gas, gas_price, call_to, execute_on_send, error_expected, call_tx_succeedes, consumes_all_gas',
    (
        (
            encode_hex(pad32(b"1283712983711973")),
            0,
            100000,
            1,
            RECEIVER.public_key.to_canonical_address(),
            False,
            False,
            True,
            False
        ),
        (
            encode_hex(pad32(b"123120371238719")),
            0,
            100000,
            1,
            RECEIVER.public_key.to_canonical_address(),
            False,
            False,
            True,
            False
        ),
        (
            encode_hex(pad32(b"123120371238719")),
            1,
            100000,
            1,
            RECEIVER.public_key.to_canonical_address(),
            False,
            False,
            True,
            False
        ),
        ( # sending more value than is in the chain. This doesn't result in an error.
            encode_hex(pad32(b"123120371238719")),
            100,
            100000,
            1,
            RECEIVER.public_key.to_canonical_address(),
            False,
            False,
            False,
            False
        ),
        ( # Sending more gas than the tx had
            encode_hex(pad32(b"123120371238719")),
            1,
            100000000000,
            1,
            RECEIVER.public_key.to_canonical_address(),
            False,
            False,
            True,
            False
        ),
        ( # not sending enough gas
            encode_hex(pad32(b"123120371238719")),
            1,
            100,
            1,
            RECEIVER.public_key.to_canonical_address(),
            False,
            'soft_error',
            True,
            False
        ),

        (
            encode_hex(pad32(b"123120371238719")),
            0,
            100000,
            1,
            RECEIVER2.public_key.to_canonical_address(),
            False,
            False,
            True,
            False
        ),
        ( # Executing on send not allowed for create. The sending block will fail to import
            encode_hex(pad32(b"123120371238719")),
            0,
            100000,
            1,
            RECEIVER2.public_key.to_canonical_address(),
            True,
            'hard_error',
            True,
            False
        ),

    )
)
def test_child_transaction_from_call_opcode(call_data, call_value, call_gas, gas_price, call_to, execute_on_send, error_expected, call_tx_succeedes, consumes_all_gas):
    #call_data = encode_hex(pad32(b"1283712983711973"))
    #call_value = 0
    #call_gas = 100000
    tx_gas = 20000000
    tx_value = 5
    #gas_price = 1
    #call_to = RECEIVER.public_key.to_canonical_address()
    code = assemble(
                # store call_data into memory
                opcode_values.PUSH32,
                call_data, # value
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(0))), # start position
                opcode_values.MSTORE,

                #store call parameters in stack
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(0))), # memory_out_length
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(0))),# memory_out_start
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(32))),# memory_in_length
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(0))),# memory_in_start
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(call_value))), # value
                opcode_values.PUSH20,
                call_to, # to
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(call_gas))), # gas

                # make the call
                opcode_values.CALL, # call
            )

    testdb = MemoryDB()
    create_predefined_blockchain_database(testdb)

    sender_chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    sender_chain.create_and_sign_transaction_for_queue_block(
        gas_price=gas_price,
        gas=tx_gas,
        to=CREATE_CONTRACT_ADDRESS,
        value=tx_value,
        data=code,
        execute_on_send=execute_on_send
    )

    sender_initial_balance = sender_chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    #
    # Checks on the transaction that was generated by the computation
    #
    if error_expected == 'hard_error':
        # We expect error on send, and the block wont send.
        with pytest.raises(Exception):
            sender_block = sender_chain.import_current_queue_block()
            deploy_address = generate_contract_address(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), sender_block.transactions[0].nonce)
            receiver_chain = TestnetChain(testdb, deploy_address, TESTNET_GENESIS_PRIVATE_KEY)
            receiver_chain.populate_queue_block_with_receive_tx()

    elif error_expected == 'soft_error':
        # we expect a vm error on send, it will use all the gas but still import the block.
        # We will raise an error when trying to receive the transaction because there is no transaction to receive.

        sender_block = sender_chain.import_current_queue_block()

        sender_final_balance = sender_chain.get_vm().state.account_db.get_balance( TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

        if consumes_all_gas:
            assert((sender_final_balance-sender_initial_balance) == (tx_value + tx_gas*gas_price))

        deploy_address = generate_contract_address(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), sender_block.transactions[0].nonce)
        receiver_chain = TestnetChain(testdb, deploy_address, TESTNET_GENESIS_PRIVATE_KEY)
        receiver_chain.populate_queue_block_with_receive_tx()

        with pytest.raises(Exception):
            receiver_block = receiver_chain.import_current_queue_block()
    else:

        sender_block = sender_chain.import_current_queue_block()
        deploy_address = generate_contract_address(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), sender_block.transactions[0].nonce)
        receiver_chain = TestnetChain(testdb, deploy_address, TESTNET_GENESIS_PRIVATE_KEY)
        receiver_chain.populate_queue_block_with_receive_tx()

        receiver_block = receiver_chain.import_current_queue_block()
        if call_tx_succeedes:
            assert(len(receiver_block.transactions) == 1)

            generated_computation_tx = receiver_block.transactions[0]

            assert (generated_computation_tx.value == call_value)
            assert (generated_computation_tx.gas_price == gas_price)
            assert (generated_computation_tx.to == call_to)
            assert (generated_computation_tx.data == decode_hex(call_data))
            assert (generated_computation_tx.caller == deploy_address)
            assert (generated_computation_tx.origin == TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
            assert (generated_computation_tx.execute_on_send == False)


            # things that change for other kinds of calls
            assert (generated_computation_tx.code_address == b'')
            assert (generated_computation_tx.create_address == b'')
        else:
            assert (len(receiver_block.transactions) == 0)




# test_child_transaction_from_call_opcode(encode_hex(pad32(b"123120371238719")),
#             0,
#             100000,
#             1,
#             RECEIVER2.public_key.to_canonical_address(),
#             False,
#             False,
#             True,
#             False)



def test_contract_deployment_gas_cost():
    call_data = encode_hex(pad32(b"1283712983711973"))
    call_value = 0
    call_gas = 100000
    tx_gas = 20000000
    tx_value = 0
    gas_price = 1
    call_to = RECEIVER.public_key.to_canonical_address()
    code = assemble(
                # store call_data into memory
                opcode_values.PUSH32,
                call_data, # value
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(0))), # start position
                opcode_values.MSTORE,

                #store call parameters in stack
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(0))), # memory_out_length
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(0))),# memory_out_start
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(32))),# memory_in_length
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(0))),# memory_in_start
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(call_value))), # value
                opcode_values.PUSH20,
                call_to, # to
                opcode_values.PUSH32,
                encode_hex(pad32(int_to_big_endian(call_gas))), # gas

                # make the call
                opcode_values.CALL, # call
            )

    testdb = MemoryDB()
    create_predefined_blockchain_database(testdb)

    sender_chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    sender_chain.create_and_sign_transaction_for_queue_block(
        gas_price=gas_price,
        gas=tx_gas,
        to=CREATE_CONTRACT_ADDRESS,
        value=tx_value,
        data=code,
    )

    sender_initial_balance = sender_chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    sender_block = sender_chain.import_current_queue_block()

    sender_final_balance = sender_chain.get_vm().state.account_db.get_balance( TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    assert((sender_initial_balance - sender_final_balance) == 158081)


# test_contract_deployment_gas_cost()



@pytest.mark.parametrize(
    'call_data, call_value, call_gas, gas_price, call_to, call_execute_on_send, error_expected, call_tx_succeedes, consumes_all_gas',
    (
        (
            encode_hex(pad32(b"123120371238719")),
            0,
            100000,
            1,
            RECEIVER.public_key.to_canonical_address(),
            False,
            False,
            True,
            False
        ),
        ( # code address is the same as the to.
            encode_hex(pad32(b"123120371238719")),
            0,
            100000,
            1,
            RECEIVER3.public_key.to_canonical_address(),
            False,
            False,
            True,
            False
        ),
        ( # the surrogatecall will have execute on send
            encode_hex(pad32(b"123120371238719")),
            0,
            100000,
            1,
            RECEIVER3.public_key.to_canonical_address(),
            True,
            False,
            True,
            False
        ),

    )
)
def test_child_transaction_from_surrogatecall_opcode(call_data, call_value, call_gas, gas_price, call_to, call_execute_on_send, error_expected, call_tx_succeedes, consumes_all_gas):
    tx_gas = 20000000
    tx_value = 5
    call_code_address = RECEIVER3.public_key.to_canonical_address()
    code = assemble(
        # store call_data into memory
        opcode_values.PUSH32,
        call_data,  # value
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(0))),  # start position
        opcode_values.MSTORE,

        # store call parameters in stack
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(32))),  # memory_in_length
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(0))),  # memory_in_start
        opcode_values.PUSH20,
        call_to,  # to
        opcode_values.PUSH1,
        encode_hex(int_to_big_endian(1 if call_execute_on_send else 0)),  # execute on send
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(call_value))),  # value
        opcode_values.PUSH20,
        call_code_address,  # code_address
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(call_gas))),  # gas

        # make the call
        opcode_values.SURROGATECALL,  # call
    )

    testdb = MemoryDB()
    create_predefined_blockchain_database(testdb)

    sender_chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    sender_chain.create_and_sign_transaction_for_queue_block(
        gas_price=gas_price,
        gas=tx_gas,
        to=CREATE_CONTRACT_ADDRESS,
        value=tx_value,
        data=code,
    )

    sender_initial_balance = sender_chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    #
    # Checks on the transaction that was generated by the computation
    #
    if error_expected == 'hard_error':
        # We expect error on send, and the block wont send.
        with pytest.raises(Exception):
            sender_block = sender_chain.import_current_queue_block()
            deploy_address = generate_contract_address(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), sender_block.transactions[0].nonce)
            receiver_chain = TestnetChain(testdb, deploy_address, TESTNET_GENESIS_PRIVATE_KEY)
            receiver_chain.populate_queue_block_with_receive_tx()

    elif error_expected == 'soft_error':
        # we expect a vm error on send, it will use all the gas but still import the block.
        # We will raise an error when trying to receive the transaction because there is no transaction to receive.

        sender_block = sender_chain.import_current_queue_block()

        sender_final_balance = sender_chain.get_vm().state.account_db.get_balance( TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

        if consumes_all_gas:
            assert((sender_final_balance-sender_initial_balance) == (tx_value + tx_gas*gas_price))

        deploy_address = generate_contract_address(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), sender_block.transactions[0].nonce)
        receiver_chain = TestnetChain(testdb, deploy_address, TESTNET_GENESIS_PRIVATE_KEY)
        receiver_chain.populate_queue_block_with_receive_tx()

        with pytest.raises(Exception):
            receiver_block = receiver_chain.import_current_queue_block()
    else:

        sender_block = sender_chain.import_current_queue_block()
        deploy_address = generate_contract_address(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), sender_block.transactions[0].nonce)
        receiver_chain = TestnetChain(testdb, deploy_address, TESTNET_GENESIS_PRIVATE_KEY)
        receiver_chain.populate_queue_block_with_receive_tx()

        receiver_block = receiver_chain.import_current_queue_block()
        if call_tx_succeedes:
            assert(len(receiver_block.transactions) == 1)

            generated_computation_tx = receiver_block.transactions[0]

            assert (generated_computation_tx.value == call_value)
            assert (generated_computation_tx.gas_price == gas_price)
            assert (generated_computation_tx.to == call_to)
            assert (generated_computation_tx.data == decode_hex(call_data))
            assert (generated_computation_tx.caller == deploy_address)
            assert (generated_computation_tx.origin == TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
            assert (generated_computation_tx.execute_on_send == call_execute_on_send)


            # things that change for other kinds of calls
            if call_code_address == call_to:
                # If the code address is the recipient of the transaction, then code address is left blank because
                # it will already be executing the code at the recipient chain.
                assert (generated_computation_tx.code_address == b'')
            else:
                assert (generated_computation_tx.code_address == call_code_address)
            assert (generated_computation_tx.create_address == b'')
        else:
            assert (len(receiver_block.transactions) == 0)


# test_child_transaction_from_surrogatecall_opcode(encode_hex(pad32(b"123120371238719")),
#             0,
#             100000,
#             1,
#             RECEIVER3.public_key.to_canonical_address(),
#             True,
#             False,
#             True,
#             False)




@pytest.mark.parametrize(
    'call_value, error_expected, call_tx_succeedes',
    (
        (
            0,
            False,
            True,
        ),
        ( # Sending value larger than on the chain. Contract deploys, but create call tx doesnt send.
            10,
            False,
            False,
        ),

    )
)
def test_child_transaction_from_create_opcode(call_value, error_expected, call_tx_succeedes):
    tx_gas = 20000000
    tx_value = 5
    gas_price = 1
    call_data = encode_hex(pad32(b"123120371238719"))
    code = assemble(
        # store call_data into memory
        opcode_values.PUSH32,
        call_data,  # value
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(0))),  # start position
        opcode_values.MSTORE,

        # store call parameters in stack
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(32))),  # memory_in_length
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(0))),  # memory_in_start
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(call_value))),  # value

        # make the call
        opcode_values.CREATE,  # create
    )

    testdb = MemoryDB()
    create_predefined_blockchain_database(testdb)

    sender_chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    sender_chain.create_and_sign_transaction_for_queue_block(
        gas_price=gas_price,
        gas=tx_gas,
        to=CREATE_CONTRACT_ADDRESS,
        value=tx_value,
        data=code,
    )



    sender_initial_balance = sender_chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    #
    # Checks on the transaction that was generated by the computation
    #
    if error_expected == 'hard_error':
        # We expect error on send, and the block wont send.
        with pytest.raises(Exception):
            sender_block = sender_chain.import_current_queue_block()
            deploy_address = generate_contract_address(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), sender_block.transactions[0].nonce)
            receiver_chain = TestnetChain(testdb, deploy_address, TESTNET_GENESIS_PRIVATE_KEY)
            receiver_chain.populate_queue_block_with_receive_tx()

    elif error_expected == 'soft_error':
        # we expect a vm error on send, it will use all the gas but still import the block.
        # We will raise an error when trying to receive the transaction because there is no transaction to receive.

        sender_block = sender_chain.import_current_queue_block()

        sender_final_balance = sender_chain.get_vm().state.account_db.get_balance( TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

        deploy_address = generate_contract_address(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), sender_block.transactions[0].nonce)
        receiver_chain = TestnetChain(testdb, deploy_address, TESTNET_GENESIS_PRIVATE_KEY)
        receiver_chain.populate_queue_block_with_receive_tx()

        with pytest.raises(Exception):
            receiver_block = receiver_chain.import_current_queue_block()
    else:

        sender_block = sender_chain.import_current_queue_block()
        deploy_address = generate_contract_address(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), sender_block.transactions[0].nonce)

        computation_call_nonce = 1
        call_expected_contract_address = generate_contract_address(
            deploy_address,
            computation_call_nonce,
        )

        receiver_chain = TestnetChain(testdb, deploy_address, TESTNET_GENESIS_PRIVATE_KEY)
        receiver_chain.populate_queue_block_with_receive_tx()

        receiver_block = receiver_chain.import_current_queue_block()
        if call_tx_succeedes:
            assert(len(receiver_block.transactions) == 1)

            generated_computation_tx = receiver_block.transactions[0]

            assert (generated_computation_tx.value == call_value)
            assert (generated_computation_tx.gas_price == gas_price)
            assert (generated_computation_tx.to == CREATE_CONTRACT_ADDRESS)
            assert (generated_computation_tx.data == decode_hex(call_data))
            assert (generated_computation_tx.caller == deploy_address)
            assert (generated_computation_tx.origin == TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
            assert (generated_computation_tx.execute_on_send == False)


            # things that change for other kinds of calls
            assert (generated_computation_tx.code_address == b'')
            assert (generated_computation_tx.create_address == call_expected_contract_address)
        else:
            assert (len(receiver_block.transactions) == 0)

# test_child_transaction_from_create_opcode(
#     10,
#     False,
#     False,
#     False
# )


@pytest.mark.parametrize(
    'call_value, error_expected, call_tx_succeedes',
    (
        (
            0,
            False,
            True,
        ),
        ( # Sending value larger than on the chain. Contract deploys, but create call tx doesnt send.
            10,
            False,
            False,
        ),

    )
)
def test_child_transaction_from_create2_opcode(call_value, error_expected, call_tx_succeedes):
    tx_gas = 20000000
    tx_value = 5
    gas_price = 1
    call_data = encode_hex(pad32(b"123120371238719"))
    salt = encode_hex(pad32(int_to_big_endian(1337)))
    code = assemble(
        # store call_data into memory
        opcode_values.PUSH32,
        call_data,  # value
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(0))),  # start position
        opcode_values.MSTORE,

        # store call parameters in stack
        opcode_values.PUSH32,
        salt,  # salt
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(32))),  # memory_in_length
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(0))),  # memory_in_start
        opcode_values.PUSH32,
        encode_hex(pad32(int_to_big_endian(call_value))),  # value

        # make the call
        opcode_values.CREATE2,  # create
    )

    testdb = MemoryDB()
    create_predefined_blockchain_database(testdb)

    sender_chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)

    sender_chain.create_and_sign_transaction_for_queue_block(
        gas_price=gas_price,
        gas=tx_gas,
        to=CREATE_CONTRACT_ADDRESS,
        value=tx_value,
        data=code,
    )



    sender_initial_balance = sender_chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    #
    # Checks on the transaction that was generated by the computation
    #
    if error_expected == 'hard_error':
        # We expect error on send, and the block wont send.
        with pytest.raises(Exception):
            sender_block = sender_chain.import_current_queue_block()
            deploy_address = generate_contract_address(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), sender_block.transactions[0].nonce)
            receiver_chain = TestnetChain(testdb, deploy_address, TESTNET_GENESIS_PRIVATE_KEY)
            receiver_chain.populate_queue_block_with_receive_tx()

    elif error_expected == 'soft_error':
        # we expect a vm error on send, it will use all the gas but still import the block.
        # We will raise an error when trying to receive the transaction because there is no transaction to receive.

        sender_block = sender_chain.import_current_queue_block()

        sender_final_balance = sender_chain.get_vm().state.account_db.get_balance( TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

        deploy_address = generate_contract_address(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), sender_block.transactions[0].nonce)
        receiver_chain = TestnetChain(testdb, deploy_address, TESTNET_GENESIS_PRIVATE_KEY)
        receiver_chain.populate_queue_block_with_receive_tx()

        with pytest.raises(Exception):
            receiver_block = receiver_chain.import_current_queue_block()
    else:

        sender_block = sender_chain.import_current_queue_block()
        deploy_address = generate_contract_address(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), sender_block.transactions[0].nonce)

        call_expected_contract_address = generate_safe_contract_address(
            deploy_address,
            1337,
            decode_hex(call_data)
        )

        receiver_chain = TestnetChain(testdb, deploy_address, TESTNET_GENESIS_PRIVATE_KEY)
        receiver_chain.populate_queue_block_with_receive_tx()

        receiver_block = receiver_chain.import_current_queue_block()
        if call_tx_succeedes:
            assert(len(receiver_block.transactions) == 1)

            generated_computation_tx = receiver_block.transactions[0]

            assert (generated_computation_tx.value == call_value)
            assert (generated_computation_tx.gas_price == gas_price)
            assert (generated_computation_tx.to == CREATE_CONTRACT_ADDRESS)
            assert (generated_computation_tx.data == decode_hex(call_data))
            assert (generated_computation_tx.caller == deploy_address)
            assert (generated_computation_tx.origin == TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
            assert (generated_computation_tx.execute_on_send == False)


            # things that change for other kinds of calls
            assert (generated_computation_tx.code_address == b'')
            assert (generated_computation_tx.create_address == call_expected_contract_address)
        else:
            assert (len(receiver_block.transactions) == 0)

# test_child_transaction_from_create2_opcode(
#     10,
#     False,
#     False,
#     False
# )


#
# Test calling functions without doing it on deployment
#

def deploy_test_contract_to_database():
    absolute_dir = os.path.dirname(os.path.realpath(__file__))
    testdb = LevelDB(absolute_dir + "/predefined_databases/test_contract")
    testdb.destroy_db()
    testdb = LevelDB(absolute_dir + "/predefined_databases/test_contract")
    create_predefined_blockchain_database(testdb)
    deployed_contract_address, contract_interface = deploy_contract(testdb, 'test_computation_calls', 'Test')
    print("Test contract deployed to {}".format(encode_hex(deployed_contract_address)))

# deploy_test_contract_to_database()
# exit()



def test_call_from_compiled():
    # testdb = MemoryDB()
    # create_predefined_blockchain_database(testdb)

    absolute_dir = os.path.dirname(os.path.realpath(__file__))
    testdb = ReadOnlyDB(LevelDB(absolute_dir + "/predefined_databases/test_contract"))
    deployed_contract_address = decode_hex('0xde4d82cbf59478edc432e03fe29f5930b14a4dd8')

    w3 = Web3()

    max_gas = 20000000

    contract_interface = compile_and_get_contract_interface('test_computation_calls', 'Test')

    tx_value = 1000
    tx_gas_price = 1
    call_to = RECEIVER.public_key.to_canonical_address()
    call_value = 100
    call_gas = 100000
    call_data = ZERO_HASH32


    #
    # Test call
    #


    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    min_time_between_blocks = chain.get_vm(timestamp=Timestamp(int(time.time()))).min_time_between_blocks

    origin_initial_balance = chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    Test = w3.hls.contract(
        address=Web3.toChecksumAddress(deployed_contract_address),
        abi=contract_interface['abi']
    )

    w3_tx = Test.functions.test_call(call_to, call_value, call_gas, call_data).buildTransaction(W3_TX_DEFAULTS)

    send_tx_1 = chain.create_and_sign_transaction_for_queue_block(
        gas_price=tx_gas_price,
        gas=max_gas,
        to=deployed_contract_address,
        value=tx_value,
        data=decode_hex(w3_tx['data']),
    )

    chain.import_current_queue_block()

    receiver_chain = TestnetChain(testdb, deployed_contract_address, TESTNET_GENESIS_PRIVATE_KEY)
    receiver_chain.populate_queue_block_with_receive_tx()

    receiver_block = receiver_chain.import_current_queue_block()

    expected_refund_1_amount = max_gas - send_tx_1.intrinsic_gas - 10065 - call_gas - GAS_TX
    refund_1_amount = receiver_block.receive_transactions[0]['remaining_refund']

    assert(expected_refund_1_amount == refund_1_amount)

    assert(len(receiver_block.transactions)==1)

    computation_call_tx = receiver_block.transactions[0]


    assert (computation_call_tx['gas'] == call_gas + GAS_CALLSTIPEND + GAS_TX)
    assert (computation_call_tx['to'] == call_to)
    assert (computation_call_tx['gas_price'] == tx_gas_price)
    assert (computation_call_tx['value'] == call_value)
    assert (computation_call_tx['data'] == call_data)
    assert (computation_call_tx['caller'] == deployed_contract_address)
    assert (computation_call_tx['origin'] == TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    # things that change for surrogate
    assert (computation_call_tx['code_address'] == b'')
    assert (computation_call_tx['create_address'] == b'')
    assert (computation_call_tx['execute_on_send'] == False)

    remaining_balance_on_contract = receiver_chain.get_vm().state.account_db.get_balance(deployed_contract_address)
    assert(remaining_balance_on_contract == tx_value-call_value)

    origin_remaining_balance = chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    # print(origin_remaining_balance-origin_initial_balance)
    # print(max_gas*tx_gas_price+tx_value)
    # print(max_gas*tx_gas_price+tx_value + (origin_remaining_balance-origin_initial_balance))
    assert (origin_remaining_balance - origin_initial_balance ==  -1*(max_gas*tx_gas_price+tx_value))


    #
    # Receive call tx and get refund
    #

    chain = TestnetChain(testdb, RECEIVER.public_key.to_canonical_address(), RECEIVER)
    initial_balance =chain.get_vm().state.account_db.get_balance(RECEIVER.public_key.to_canonical_address())
    chain.populate_queue_block_with_receive_tx()
    block = chain.import_current_queue_block()
    final_balance = chain.get_vm().state.account_db.get_balance(RECEIVER.public_key.to_canonical_address())
    assert(final_balance-initial_balance==call_value)

    refund_2_amount = block.receive_transactions[0]['remaining_refund']

    expected_refund_2_amount = call_gas + GAS_CALLSTIPEND + GAS_TX - computation_call_tx.intrinsic_gas
    print(expected_refund_2_amount)
    print(refund_2_amount)
    assert (expected_refund_2_amount == refund_2_amount)

    #it will receive 2 refunds as long as all the gas wasn't used for the call
    # on the call that uses all gas, make sure the first tx doesnt generate a refund


    print("waiting {} seconds before importing next block".format(min_time_between_blocks))
    time.sleep(min_time_between_blocks)

    origin_chain =  TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    origin_chain.populate_queue_block_with_receive_tx()
    origin_chain.import_current_queue_block()

    # make sure there are no more receivable transactions
    assert(len(origin_chain.create_receivable_transactions())==0)
    origin_final_balance = origin_chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    #Refund was the amount expected from the two refund transactions
    expected_origin_final_balance = origin_initial_balance - max_gas - tx_value + refund_1_amount + refund_2_amount
    assert(origin_final_balance == expected_origin_final_balance)




# test_call_from_compiled()
# exit()


def test_surrogatecall_from_compiled():
    # testdb = MemoryDB()
    # create_predefined_blockchain_database(testdb)

    absolute_dir = os.path.dirname(os.path.realpath(__file__))
    testdb = ReadOnlyDB(LevelDB(absolute_dir + "/predefined_databases/test_contract"))
    deployed_contract_address = decode_hex('0xde4d82cbf59478edc432e03fe29f5930b14a4dd8')

    w3 = Web3()

    max_gas = 20000000

    contract_interface = compile_and_get_contract_interface('test_computation_calls', 'Test')

    tx_value = 1000
    tx_gas_price = 1
    call_to = RECEIVER.public_key.to_canonical_address()
    call_code_address = RECEIVER2.public_key.to_canonical_address()
    call_execute_on_send = True
    call_value = 100
    call_gas = 100000
    call_data = ZERO_HASH32

    #
    # Test call
    #

    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    min_time_between_blocks = chain.get_vm(timestamp=Timestamp(int(time.time()))).min_time_between_blocks

    origin_initial_balance = chain.get_vm().state.account_db.get_balance(
        TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    Test = w3.hls.contract(
        address=Web3.toChecksumAddress(deployed_contract_address),
        abi=contract_interface['abi']
    )

    w3_tx = Test.functions.test_surrogatecall(call_code_address, call_to, call_execute_on_send, call_value, call_gas, call_data).buildTransaction(W3_TX_DEFAULTS)

    send_tx_1 = chain.create_and_sign_transaction_for_queue_block(
        gas_price=tx_gas_price,
        gas=max_gas,
        to=deployed_contract_address,
        value=tx_value,
        data=decode_hex(w3_tx['data']),
    )

    chain.import_current_queue_block()

    receiver_chain = TestnetChain(testdb, deployed_contract_address, TESTNET_GENESIS_PRIVATE_KEY)
    receiver_chain.populate_queue_block_with_receive_tx()

    receiver_block = receiver_chain.import_current_queue_block()

    expected_refund_1_amount = max_gas - send_tx_1.intrinsic_gas - 9541 - call_gas
    refund_1_amount = receiver_block.receive_transactions[0]['remaining_refund']

    assert (expected_refund_1_amount == refund_1_amount)

    assert (len(receiver_block.transactions) == 1)

    computation_call_tx = receiver_block.transactions[0]

    assert (computation_call_tx['gas'] == call_gas + GAS_CALLSTIPEND)
    assert (computation_call_tx['to'] == call_to)
    assert (computation_call_tx['gas_price'] == tx_gas_price)
    assert (computation_call_tx['value'] == call_value)
    assert (computation_call_tx['data'] == call_data)
    assert (computation_call_tx['caller'] == deployed_contract_address)
    assert (computation_call_tx['origin'] == TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    # things that change for surrogate
    assert (computation_call_tx['code_address'] == call_code_address)
    assert (computation_call_tx['create_address'] == b'')
    assert (computation_call_tx['execute_on_send'] == call_execute_on_send)

    remaining_balance_on_contract = receiver_chain.get_vm().state.account_db.get_balance(deployed_contract_address)
    assert (remaining_balance_on_contract == tx_value - call_value)

    origin_remaining_balance = chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    # print(origin_remaining_balance-origin_initial_balance)
    # print(max_gas*tx_gas_price+tx_value)
    # print(max_gas*tx_gas_price+tx_value + (origin_remaining_balance-origin_initial_balance))
    assert (origin_remaining_balance - origin_initial_balance == -1 * (max_gas * tx_gas_price + tx_value))

    #
    # Receive call tx and get refund
    #

    chain = TestnetChain(testdb, RECEIVER.public_key.to_canonical_address(), RECEIVER)
    initial_balance = chain.get_vm().state.account_db.get_balance(RECEIVER.public_key.to_canonical_address())
    chain.populate_queue_block_with_receive_tx()
    block = chain.import_current_queue_block()
    final_balance = chain.get_vm().state.account_db.get_balance(RECEIVER.public_key.to_canonical_address())
    assert (final_balance - initial_balance == call_value)

    refund_2_amount = block.receive_transactions[0]['remaining_refund']

    expected_refund_2_amount = call_gas + GAS_CALLSTIPEND - computation_call_tx.intrinsic_gas
    assert (expected_refund_2_amount == refund_2_amount)

    # it will receive 2 refunds as long as all the gas wasn't used for the call
    # on the call that uses all gas, make sure the first tx doesnt generate a refund

    print("waiting {} seconds before importing next block".format(min_time_between_blocks))
    time.sleep(min_time_between_blocks)

    origin_chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                                TESTNET_GENESIS_PRIVATE_KEY)
    origin_chain.populate_queue_block_with_receive_tx()
    origin_chain.import_current_queue_block()

    # make sure there are no more receivable transactions
    assert (len(origin_chain.create_receivable_transactions()) == 0)
    origin_final_balance = origin_chain.get_vm().state.account_db.get_balance(
        TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    # Refund was the amount expected from the two refund transactions
    expected_origin_final_balance = origin_initial_balance - max_gas - tx_value + refund_1_amount + refund_2_amount
    assert (origin_final_balance == expected_origin_final_balance)


test_surrogatecall_from_compiled()
exit()


def test_send_from_compiled():
    # testdb = MemoryDB()
    # create_predefined_blockchain_database(testdb)

    absolute_dir = os.path.dirname(os.path.realpath(__file__))
    testdb = ReadOnlyDB(LevelDB(absolute_dir + "/predefined_databases/test_contract"))
    deployed_contract_address = decode_hex('0xde4d82cbf59478edc432e03fe29f5930b14a4dd8')

    w3 = Web3()

    max_gas = 20000000

    contract_interface = compile_and_get_contract_interface('test_computation_calls', 'Test')

    tx_value = 1000
    tx_gas_price = 1
    call_to = RECEIVER.public_key.to_canonical_address()
    call_value = 100

    #
    # Test call
    #

    chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), TESTNET_GENESIS_PRIVATE_KEY)
    min_time_between_blocks = chain.get_vm(timestamp=Timestamp(int(time.time()))).min_time_between_blocks

    origin_initial_balance = chain.get_vm().state.account_db.get_balance(
        TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    Test = w3.hls.contract(
        address=Web3.toChecksumAddress(deployed_contract_address),
        abi=contract_interface['abi']
    )

    # address payable call_to, uint256 call_value
    w3_tx = Test.functions.test_send(call_to, call_value).buildTransaction(W3_TX_DEFAULTS)

    send_tx_1 = chain.create_and_sign_transaction_for_queue_block(
        gas_price=tx_gas_price,
        gas=max_gas,
        to=deployed_contract_address,
        value=tx_value,
        data=decode_hex(w3_tx['data']),
    )

    chain.import_current_queue_block()

    receiver_chain = TestnetChain(testdb, deployed_contract_address, TESTNET_GENESIS_PRIVATE_KEY)
    receiver_chain.populate_queue_block_with_receive_tx()

    receiver_block = receiver_chain.import_current_queue_block()

    expected_refund_1_amount = max_gas - send_tx_1.intrinsic_gas
    refund_1_amount = receiver_block.receive_transactions[0]['remaining_refund']

    print(refund_1_amount)
    assert (expected_refund_1_amount == refund_1_amount)

    assert (len(receiver_block.transactions) == 1)

    computation_call_tx = receiver_block.transactions[0]

    assert (computation_call_tx['gas'] == call_gas + GAS_CALLSTIPEND)
    assert (computation_call_tx['to'] == call_to)
    assert (computation_call_tx['gas_price'] == tx_gas_price)
    assert (computation_call_tx['value'] == call_value)
    assert (computation_call_tx['data'] == call_data)
    assert (computation_call_tx['caller'] == deployed_contract_address)
    assert (computation_call_tx['origin'] == TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    # things that change for surrogate
    assert (computation_call_tx['code_address'] == call_code_address)
    assert (computation_call_tx['create_address'] == b'')
    assert (computation_call_tx['execute_on_send'] == call_execute_on_send)

    remaining_balance_on_contract = receiver_chain.get_vm().state.account_db.get_balance(deployed_contract_address)
    assert (remaining_balance_on_contract == tx_value - call_value)

    origin_remaining_balance = chain.get_vm().state.account_db.get_balance(TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())
    # print(origin_remaining_balance-origin_initial_balance)
    # print(max_gas*tx_gas_price+tx_value)
    # print(max_gas*tx_gas_price+tx_value + (origin_remaining_balance-origin_initial_balance))
    assert (origin_remaining_balance - origin_initial_balance == -1 * (max_gas * tx_gas_price + tx_value))

    #
    # Receive call tx and get refund
    #

    chain = TestnetChain(testdb, RECEIVER.public_key.to_canonical_address(), RECEIVER)
    initial_balance = chain.get_vm().state.account_db.get_balance(RECEIVER.public_key.to_canonical_address())
    chain.populate_queue_block_with_receive_tx()
    block = chain.import_current_queue_block()
    final_balance = chain.get_vm().state.account_db.get_balance(RECEIVER.public_key.to_canonical_address())
    assert (final_balance - initial_balance == call_value)

    refund_2_amount = block.receive_transactions[0]['remaining_refund']

    expected_refund_2_amount = call_gas + GAS_CALLSTIPEND - computation_call_tx.intrinsic_gas
    assert (expected_refund_2_amount == refund_2_amount)

    # it will receive 2 refunds as long as all the gas wasn't used for the call
    # on the call that uses all gas, make sure the first tx doesnt generate a refund

    print("waiting {} seconds before importing next block".format(min_time_between_blocks))
    time.sleep(min_time_between_blocks)

    origin_chain = TestnetChain(testdb, TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                                TESTNET_GENESIS_PRIVATE_KEY)
    origin_chain.populate_queue_block_with_receive_tx()
    origin_chain.import_current_queue_block()

    # make sure there are no more receivable transactions
    assert (len(origin_chain.create_receivable_transactions()) == 0)
    origin_final_balance = origin_chain.get_vm().state.account_db.get_balance(
        TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address())

    # Refund was the amount expected from the two refund transactions
    expected_origin_final_balance = origin_initial_balance - max_gas - tx_value + refund_1_amount + refund_2_amount
    assert (origin_final_balance == expected_origin_final_balance)


test_send_from_compiled()