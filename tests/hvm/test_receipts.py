
from hvm import MainnetChain
from hvm.chains.mainnet import (
    GENESIS_PRIVATE_KEY,
    MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)

from hvm.constants import (
   GAS_TX)

from hvm.db.backends.memory import MemoryDB

from eth_utils import (
    decode_hex,
)
from helios.dev_tools import create_dev_test_random_blockchain_database, create_predefined_blockchain_database

from eth_keys import keys
from hvm.constants import random_private_keys

def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(random_private_keys[instance_number])

SENDER = GENESIS_PRIVATE_KEY
RECEIVER = get_primary_node_private_helios_key(1)
RECEIVER2 = get_primary_node_private_helios_key(2)
RECEIVER3 = get_primary_node_private_helios_key(3)
RECEIVER4 = get_primary_node_private_helios_key(4)
RECEIVER5 = get_primary_node_private_helios_key(5)


def test_get_receipts():
    testdb2 = MemoryDB()

    MainnetChain.from_genesis(testdb2, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)


    """
    Create some receive transactions for RECEIVER
    """
    sender_chain = MainnetChain(testdb2, SENDER.public_key.to_canonical_address(), SENDER)
    for i in range(6):
        sender_chain.create_and_sign_transaction_for_queue_block(
            gas_price=i+1,
            gas=0x0c3500,
            to=RECEIVER.public_key.to_canonical_address(),
            value=i+ 100000000000,
            data=b"",
            v=0,
            r=0,
            s=0
        )


    sender_chain.import_current_queue_block()
    receiver_chain = MainnetChain(testdb2, RECEIVER.public_key.to_canonical_address(), RECEIVER)
    receiver_chain.populate_queue_block_with_receive_tx()
    imported_block_1 = receiver_chain.import_current_queue_block()

    print('KKKKKKKKKKKK')
    print(RECEIVER.public_key.to_address())
    print(sender_chain.get_vm().state.account_db.get_balance(SENDER.public_key.to_canonical_address()))
    print(sender_chain.get_vm().state.account_db.get_balance(RECEIVER.public_key.to_canonical_address()))
    """
    Create some send transactions for RECEIVER
    """
    receiver_chain = MainnetChain(testdb2, RECEIVER.public_key.to_canonical_address(), RECEIVER)
    for i in range(6):
        receiver_chain.create_and_sign_transaction_for_queue_block(
            gas_price=i+1,
            gas=0x0c3500,
            to=SENDER.public_key.to_canonical_address(),
            value=i,
            data=b"",
            v=0,
            r=0,
            s=0
        )

    """
    Create a transaction with data in it.
    """
    from contract_data.compiled_contract import w3_transaction_object
    from hvm.constants import CREATE_CONTRACT_ADDRESS

    receiver_chain.create_and_sign_transaction_for_queue_block(
        gas_price=0x01,
        gas=1375666,
        to=CREATE_CONTRACT_ADDRESS,
        value=0,
        data=decode_hex(w3_transaction_object['data']),
        v=0,
        r=0,
        s=0
    )


    receiver_chain.populate_queue_block_with_receive_tx()
    imported_block = receiver_chain.import_current_queue_block()

    for i in range(7):
        if i < 6:
            receipt = sender_chain.chaindb.get_transaction_receipt(imported_block.transactions[i].hash)
            assert(receipt.status_code == b'\x01')
            assert (receipt.gas_used == GAS_TX)
            assert (receipt.bloom == 0)
            assert (receipt.logs == ())
        if i == 6:
            receipt = sender_chain.chaindb.get_transaction_receipt(imported_block.transactions[i].hash)
            assert (receipt.status_code == b'\x01')
            assert (receipt.gas_used == 1375666)
            assert (receipt.bloom == 243379359099696592952569079439667912256345493617967967903663341910531480774353059570732838085077727505416158987674861080353852392619637689071728561054211502067278701792094127192831079015338935810676425927305370163403783027301927515372719270157454901551766020292792184739669125690737609931485501648741152187826071626833444578979111366057983284511641401113379885201162016756050289195516614302086913696386892161910800529278878068496138240)
            assert (len(receipt.logs) == 1)

    for i in range(6):
        receipt = sender_chain.chaindb.get_transaction_receipt(imported_block_1.receive_transactions[i].hash)
        assert (receipt.status_code == b'\x01')
        assert (receipt.gas_used == 0)
        assert (receipt.bloom == 0)
        assert (receipt.logs == ())


test_get_receipts()