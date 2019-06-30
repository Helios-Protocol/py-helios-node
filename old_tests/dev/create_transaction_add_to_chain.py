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
    GENESIS_PRIVATE_KEY_FOR_TESTNET,
    TPC_CAP_TEST_GENESIS_PRIVATE_KEY,
    MAINNET_NETWORK_ID,
)


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
from hvm.vm.forks.helios_testnet.blocks import HeliosMicroBlock, HeliosTestnetBlock

primary_private_keys = random_private_keys
def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(primary_private_keys[instance_number])

SENDER = GENESIS_PRIVATE_KEY_FOR_TESTNET
RECEIVER = get_primary_node_private_helios_key(1)
RECEIVER2 = get_primary_node_private_helios_key(2)
RECEIVER3 = get_primary_node_private_helios_key(3)
RECEIVER4 = get_primary_node_private_helios_key(4)

from hvm.constants import GENESIS_PARENT_HASH
from eth_utils import is_hex_address

log_level = getattr(logging, 'DEBUG')
#log_level = getattr(logging, 'INFO')
logger, log_queue, listener = setup_helios_logging(log_level)
logger.propagate = False
#logger.info(HELIOS_HEADER)
from helios.rpc.format import block_to_dict

import eth_keyfile

import sys
sys.path.append('/d:/Google Drive/forex/blockchain_coding/Helios/prototype desktop/helios_deploy/')
from deploy_params import (
    genesis_private_key,
    airdrop_private_key,
    bounties_private_key,
    exchange_listings_private_key,
    dapp_incubator_private_key,
    bootnode_1_private_key,
    bootnode_2_private_key,
    masternode_1_private_key,
)

def create_new_genesis_params_and_state():
    #
    # GENESIS STATE, HEADER PARAMS
    #

    new_genesis_private_key = genesis_private_key
    print("Ceating new genesis params and state for genesis wallet address:")
    print(new_genesis_private_key.public_key.to_canonical_address())

    total_supply = 350000000 * 10 ** 18
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
        'timestamp': 1556733839,
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
    genesis_header = MainnetChain.create_genesis_header(testdb1,
                                                        new_genesis_private_key.public_key.to_canonical_address(),
                                                        new_genesis_private_key, new_mainnet_genesis_params,
                                                        new_genesis_state)

    print()
    print("New completed and signed genesis header params")
    parameter_names = list(dict(genesis_header._meta.fields).keys())
    header_params = {}
    for parameter_name in parameter_names:
        header_params[parameter_name] = getattr(genesis_header, parameter_name)
    print(header_params)
    print()


    # TPC TEST STATE, HEADER PARAMS

    # new_genesis_private_key = TPC_CAP_TEST_GENESIS_PRIVATE_KEY
    # print(new_genesis_private_key.public_key.to_canonical_address())
    #
    # testdb1 = MemoryDB()
    # genesis_header = MainnetChain.create_genesis_header(testdb1,
    #                                                     new_genesis_private_key.public_key.to_canonical_address(),
    #                                                     new_genesis_private_key, new_mainnet_genesis_params,
    #                                                     new_genesis_state)
    #
    # print()
    # print("New completed and signed tpc test header params")
    # parameter_names = list(dict(genesis_header._meta.fields).keys())
    # header_params = {}
    # for parameter_name in parameter_names:
    #     header_params[parameter_name] = getattr(genesis_header, parameter_name)
    # print(header_params)
    # print()
    #
    # db = MemoryDB()
    # chain = MainnetChain.from_genesis(db,
    #                                   TPC_CAP_TEST_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
    #                                   header_params,
    #                                   new_genesis_state,
    #                                   private_key=TPC_CAP_TEST_GENESIS_PRIVATE_KEY)
    #
    # receiver_privkey = keys.PrivateKey(random_private_keys[0])
    #
    # chain.create_and_sign_transaction_for_queue_block(
    #     gas_price=0x01,
    #     gas=0x0c3500,
    #     to=receiver_privkey.public_key.to_canonical_address(),
    #     value=1000,
    #     data=b"",
    #     v=0,
    #     r=0,
    #     s=0
    # )
    #
    # imported_block = chain.import_current_queue_block()
    #
    # block_dict = imported_block.to_dict()
    # print("TPC test block to import")
    # print(block_dict)



create_new_genesis_params_and_state()
exit()

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