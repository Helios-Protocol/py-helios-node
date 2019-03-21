from typing import Tuple, Type  # noqa: F401
from eth_utils import decode_hex

from .constants import (
    HELIOS_TESTNET_TIMESTAMP,
)
from hvm import constants

from hvm.chains import Chain
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
        "balance": 100000000000000000000000000,
        "code": b"",
        "nonce": 0,
        "storage": {}
    }
}

MAINNET_GENESIS_PARAMS = {'chain_address': b"\xdbL\xa4&\xd5;Y\xf6\x03p'O\xfb\x19\xf2&\x8d\xc3=\xdf", 'parent_hash': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 'transaction_root': b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', 'receive_transaction_root': b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', 'receipt_root': b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', 'bloom': 0, 'block_number': 0, 'gas_limit': 31415926, 'gas_used': 0, 'timestamp': 1543700000, 'extra_data': b'', 'reward_hash': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 'account_hash': b'\x19\xfc\x94\x8d\x95\xacs\x06Db\x80\xf4\x9e\x94\x823\xa1\xe2#\x03t\x0f\x8d\\\xe9\x7f&;\xc9d\xc67', 'account_balance': 100000000000000000000000000, 'v': 38, 'r': 45034268824120027712675756355413116720367789723148269550183865435685699800523, 's': 27141080959376664758566629966709756538095401130381810437562609117602786161669}


class BaseMainnetChain:
    vm_configuration = MAINNET_VM_CONFIGURATION  # type: Tuple[Tuple[int, Type[BaseVM]], ...]  # noqa: E501
    network_id = MAINNET_NETWORK_ID  # type: int
    genesis_wallet_address = GENESIS_WALLET_ADDRESS
    genesis_block_timestamp = MAINNET_GENESIS_PARAMS['timestamp']

class MainnetChain(BaseMainnetChain, Chain):
    pass


############
### tpc calculation state
############


TPC_CAP_TEST_GENESIS_PRIVATE_KEY = keys.PrivateKey(b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5')
    
MAINNET_TPC_CAP_TEST_GENESIS_STATE = {
    GENESIS_PRIVATE_KEY.public_key.to_canonical_address(): {
        "balance": 100000000000000000000000000,
        "code": b"",
        "nonce": 0,
        "storage": {}
    }
}

MAINNET_TPC_CAP_TEST_GENESIS_PARAMS =  {'chain_address': b"\xdbL\xa4&\xd5;Y\xf6\x03p'O\xfb\x19\xf2&\x8d\xc3=\xdf", 'parent_hash': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 'transaction_root': b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', 'receive_transaction_root': b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', 'receipt_root': b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', 'bloom': 0, 'block_number': 0, 'gas_limit': 31415926, 'gas_used': 0, 'timestamp': 1543700000, 'extra_data': b'', 'reward_hash': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 'account_hash': b'\x19\xfc\x94\x8d\x95\xacs\x06Db\x80\xf4\x9e\x94\x823\xa1\xe2#\x03t\x0f\x8d\\\xe9\x7f&;\xc9d\xc67', 'account_balance': 100000000000000000000000000, 'v': 38, 'r': 45034268824120027712675756355413116720367789723148269550183865435685699800523, 's': 27141080959376664758566629966709756538095401130381810437562609117602786161669}

MAINNET_TPC_CAP_TEST_BLOCK_TO_IMPORT = {'header': {'chain_address': b"\xdbL\xa4&\xd5;Y\xf6\x03p'O\xfb\x19\xf2&\x8d\xc3=\xdf", 'parent_hash': b"'\r\xa2\x14\xc6\x9a\x1f\xb6\t\xd1\x9aK\x8b\x88!M$$\x82zY\xc8j\x02\x9b\xc2B\xd9tyY\x0c", 'transaction_root': b'\xd2\xacI\x97\xbe\xa5\x03\xa8\r\x8dCN\xa0\xf8\xc5x\xe6\x08\xf5\x06\xb0\xafP\xcd\xc3hh6\xcc\xecm.', 'receive_transaction_root': b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', 'receipt_root': b'\x05k#\xfb\xbaH\x06\x96\xb6_\xe5\xa5\x9b\x8f!H\xa1)\x91\x03\xc4\xf5}\xf89#:\xf2\xcfL\xa2\xd2', 'bloom': 0, 'block_number': 1, 'gas_limit': 31415926, 'gas_used': 21000, 'timestamp': 1545443194, 'extra_data': b'', 'reward_hash': b'\xb4\xf57XD\xe9kwmz\x94ua\xa4\xf9\xd0E\xf5\xe8\r\x06\x92\x1d\x96\xe4c\xcc\xe0x\xa2F\xcc', 'account_hash': b'\xe8\xef\x99\xf9\xaee$C\t`\xbf\x1f\xd2\x83ih\xe7\xd3\xae\x08\x94i&:l\xf4\x17L\xbe\xd8"g', 'account_balance': 99999999999999999999978000, 'v': 37, 'r': 36376234874287917820385664221661071745030952243503605488463667881359108355739, 's': 32174960529346030541390403763163042149627201577806031912714703217199098028833}, 'transactions': [{'nonce': 0, 'gas_price': 1, 'gas': 800000, 'to': b'\x9c\x8b \xe80\xc0\xdb\x83\x86(\x92\xfc\x14\x18\x08\xeajQ\xfe\xa2', 'value': 1000, 'data': b'', 'v': 38, 'r': 9211576816955818479534985612931059580667889439589110209251686160194240608704, 's': 349855995276884274877483845384037637676219851703344002801559994255562224687}], 'receive_transactions': [], 'reward_bundle': {'reward_type_1': {'amount': 0}, 'reward_type_2': {'amount': 0, 'proof': []}}}




