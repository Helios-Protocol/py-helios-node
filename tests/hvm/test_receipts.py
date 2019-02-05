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

    COLLATION_SIZE, GAS_TX)


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
from helios.dev_tools import create_dev_test_random_blockchain_database, create_predefined_blockchain_database
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


def test_get_receipts():
    testdb = MemoryDB()
    create_predefined_blockchain_database(testdb)

    """
    Create some receive transactions for RECEIVER
    """
    sender_chain = MainnetChain(testdb, SENDER.public_key.to_canonical_address(), SENDER)
    for i in range(6):
        sender_chain.create_and_sign_transaction_for_queue_block(
            gas_price=i+1,
            gas=0x0c3500,
            to=RECEIVER.public_key.to_canonical_address(),
            value=i,
            data=b"",
            v=0,
            r=0,
            s=0
        )


    sender_chain.import_current_queue_block()

    """
    Create some send transactions for RECEIVER
    """
    receiver_chain = MainnetChain(testdb, RECEIVER.public_key.to_canonical_address(), RECEIVER)
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
        receipt = sender_chain.chaindb.get_transaction_receipt(imported_block.receive_transactions[i].hash)
        assert (receipt.status_code == b'\x01')
        assert (receipt.gas_used == 0)
        assert (receipt.bloom == 0)
        assert (receipt.logs == ())


test_get_receipts()