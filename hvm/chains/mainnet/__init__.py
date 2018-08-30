from typing import Tuple, Type  # noqa: F401
from eth_utils import decode_hex

from .constants import (
    HELIOS_TESTNET_TIMESTAMP,
)
from hvm import constants

from hvm.chains.base import Chain
from hvm.rlp.headers import BlockHeader
from hvm.vm.base import BaseVM  # noqa: F401
from hvm.vm.forks import (
    HeliosTestnetVM
)

from eth_keys import keys


#MAINNET_VM_CONFIGURATION = (
#    (0, FrontierVM),
#    (HOMESTEAD_MAINNET_BLOCK, HomesteadVM),
#    (TANGERINE_WHISTLE_MAINNET_BLOCK, TangerineWhistleVM),
#    (SPURIOUS_DRAGON_MAINNET_BLOCK, SpuriousDragonVM),
#    (BYZANTIUM_MAINNET_BLOCK, ByzantiumVM),
#)

MAINNET_VM_CONFIGURATION = (
    (HELIOS_TESTNET_TIMESTAMP, HeliosTestnetVM),
)


MAINNET_NETWORK_ID = 1


GENESIS_PRIVATE_KEY = keys.PrivateKey(b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5')
GENESIS_WALLET_ADDRESS = b"\xdbL\xa4&\xd5;Y\xf6\x03p'O\xfb\x19\xf2&\x8d\xc3=\xdf"

class BaseMainnetChain:
    vm_configuration = MAINNET_VM_CONFIGURATION  # type: Tuple[Tuple[int, Type[BaseVM]], ...]  # noqa: E501
    network_id = MAINNET_NETWORK_ID  # type: int
    genesis_wallet_address = GENESIS_WALLET_ADDRESS


class MainnetChain(BaseMainnetChain, Chain):
    pass


#RECEIVER = keys.PrivateKey(b'\x16\xc3\xb37\xb8\x8aG`\xdf\xad\xe3},\x9a\xb4~\xff7&?\xab\x80\x03\xf8\x9fo/:c\x18\xaa>')
#RECEIVER2 = keys.PrivateKey(b'\xd8>Fh\xefT\x04jf\x13\xca|E\xc4\x91\xed\x07\xcd\x02fW\xd8s;\xd8\xe4\xde\xb9\xbc\xe4\xf0I')

#MAINNET_GENESIS_HEADER = BlockHeader(
#    difficulty=17179869184,
#    extra_data=decode_hex("0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa"),
#    gas_limit=5000,
#    gas_used=0,
#    bloom=0,
#    mix_hash=constants.ZERO_HASH32,
#    nonce=constants.GENESIS_NONCE,
#    block_number=0,
#    parent_hash=constants.ZERO_HASH32,
#    receipt_root=constants.BLANK_ROOT_HASH,
#    uncles_hash=constants.EMPTY_UNCLE_HASH,
#    state_root=decode_hex("0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544"),
#    timestamp=0,
#    transaction_root=constants.BLANK_ROOT_HASH,
#)
    
#MAINNET_GENESIS_HEADER = BlockHeader(
#    account_hash=constants.GENESIS_ACCOUNT_HASH,
#    extra_data=decode_hex("0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa"),
#    gas_limit=5000,
#    gas_used=0,
#    bloom=0,
#    block_number=0,
#    parent_hash=constants.ZERO_HASH32,
#    receipt_root=constants.BLANK_ROOT_HASH,
#    timestamp=0,
#    transaction_root=constants.BLANK_ROOT_HASH,
#    receive_transaction_root=constants.BLANK_ROOT_HASH,
#)

#MAINNET_GENESIS_PARAMS = {
#    'account_hash':constants.GENESIS_ACCOUNT_HASH,
#    'parent_hash': constants.GENESIS_PARENT_HASH,
#    'transaction_root': constants.BLANK_ROOT_HASH,
#    'receive_transaction_root': constants.BLANK_ROOT_HASH,
#    'receipt_root': constants.BLANK_ROOT_HASH,
#    'bloom': 0,
#    'block_number': constants.GENESIS_BLOCK_NUMBER,
#    'gas_limit': constants.GENESIS_GAS_LIMIT,
#    'gas_used': 0,
#    'timestamp': 1514764800,
#    'extra_data': constants.GENESIS_EXTRA_DATA
#}


#this state and header must go together to be valid.
MAINNET_GENESIS_STATE = {
    GENESIS_PRIVATE_KEY.public_key.to_canonical_address(): {
        "balance": 1000000000000000000000000,
        "code": b"",
        "nonce": 0,
        "storage": {}
    }
}

MAINNET_GENESIS_PARAMS =    {'parent_hash': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 
                             'transaction_root': b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', 
                             'receive_transaction_root': b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', 
                             'receipt_root': b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', 
                             'bloom': 0, 
                             'block_number': 0, 
                             'gas_limit': 3141592, 
                             'gas_used': 0, 
                             'timestamp': 1534540000, 
                             'extra_data': b'', 
                             'account_hash': b'\xcf`o\x0f\x18V\xc1=\x12\xb03S!D\xc13\xf8\xa7\xb6\xa6\xd5\x97\xd8\xc0\x0e\xc2r\x16\xc1\xd2\xa2\xdf', 
                             'v': 38, 
                             'r': 43925323656067586507211437838703170780050555607290501798403532393106951756542, 
                             's': 470229672062199396468266522076242487732209668233860526403123000492519192994}



    
    
    
TPC_CAP_TEST_GENESIS_PRIVATE_KEY = keys.PrivateKey(b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5')
    
MAINNET_TPC_CAP_TEST_GENESIS_STATE = {
    GENESIS_PRIVATE_KEY.public_key.to_canonical_address(): {
        "balance": 1000000000000000000000000,
        "code": b"",
        "nonce": 0,
        "storage": {}
    }
}

MAINNET_TPC_CAP_TEST_GENESIS_PARAMS =    {'parent_hash': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 
                             'transaction_root': b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', 
                             'receive_transaction_root': b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', 
                             'receipt_root': b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', 
                             'bloom': 0, 
                             'block_number': 0, 
                             'gas_limit': 3141592, 
                             'gas_used': 0, 
                             'timestamp': 1532470000, 
                             'extra_data': b'', 
                             'account_hash': b'\xcf`o\x0f\x18V\xc1=\x12\xb03S!D\xc13\xf8\xa7\xb6\xa6\xd5\x97\xd8\xc0\x0e\xc2r\x16\xc1\xd2\xa2\xdf', 
                             'v': 37, 
                             'r': 27003253526022851361797746803314279807537188107766227981548245111422237778762, 
                             's': 19879697156142810027206173065379415356577523422925107713843487402274342088642}