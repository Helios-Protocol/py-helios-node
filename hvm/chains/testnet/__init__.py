from typing import Tuple, Type  # noqa: F401
from eth_utils import decode_hex

from hvm.constants import TESTNET_FAUCET_PRIVATE_KEY
from hvm.vm.forks.boson import BosonVM
from .constants import (
    HELIOS_TESTNET_TIMESTAMP,
    BOSON_TIMESTAMP,
PHOTON_TIMESTAMP)
from hvm import constants

from hvm.vm.forks.photon import PhotonVM
from hvm.chains import Chain
from hvm.rlp.headers import BlockHeader
from hvm.vm.base import BaseVM  # noqa: F401
from hvm.vm.forks import (
    HeliosTestnetVM
)
from eth_typing import Address

from eth_keys import keys
from eth_keys.datatypes import PrivateKey

from hvm.types import Timestamp

from eth_utils import to_wei
from eth_utils import encode_hex, decode_hex

TESTNET_VM_CONFIGURATION = (
    (HELIOS_TESTNET_TIMESTAMP, HeliosTestnetVM),
    (BOSON_TIMESTAMP, BosonVM),
    (PHOTON_TIMESTAMP, PhotonVM),
)

TESTNET_NETWORK_ID = 2

TESTNET_GENESIS_PRIVATE_KEY = keys.PrivateKey(b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5')

TESTNET_GENESIS_STATE = {
    TESTNET_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(): {
        "balance": 100000000000000000000000000,
        "code": b"",
        "nonce": 0,
        "storage": {}
    }
}

import time
from hvm.validation import validate_uint256
from hvm.exceptions import VMNotFound

TESTNET_GENESIS_PARAMS =  {'chain_address': b"\xdbL\xa4&\xd5;Y\xf6\x03p'O\xfb\x19\xf2&\x8d\xc3=\xdf", 'parent_hash': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 'transaction_root': b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', 'receive_transaction_root': b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', 'receipt_root': b'V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!', 'bloom': 0, 'block_number': 0, 'gas_limit': 31415926, 'gas_used': 0, 'timestamp': 1543700000, 'extra_data': b'', 'reward_hash': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 'account_hash': b'\x19\xfc\x94\x8d\x95\xacs\x06Db\x80\xf4\x9e\x94\x823\xa1\xe2#\x03t\x0f\x8d\\\xe9\x7f&;\xc9d\xc67', 'account_balance': 100000000000000000000000000, 'v': 38, 'r': 45034268824120027712675756355413116720367789723148269550183865435685699800523, 's': 27141080959376664758566629966709756538095401130381810437562609117602786161669}

TESTNET_GENESIS_WALLET_ADDRESS = TESTNET_GENESIS_PARAMS['chain_address']

class BaseTestnetChain:
    faucet_private_key: PrivateKey = keys.PrivateKey(TESTNET_FAUCET_PRIVATE_KEY)
    vm_configuration: Tuple[Tuple[Timestamp, Type[BaseVM]]] = TESTNET_VM_CONFIGURATION
    network_id: int = TESTNET_NETWORK_ID
    genesis_wallet_address: Address = TESTNET_GENESIS_PARAMS['chain_address']
    genesis_block_timestamp: Timestamp = TESTNET_GENESIS_PARAMS['timestamp']

class TestnetChain(BaseTestnetChain, Chain):
    pass

class TestnetTesterChain(TestnetChain, Chain):
    def set_fixed_vm_for_timestamp(self, timestamp):
        '''
          Finds the correct VM for the given timestamp, and fixes the chain to that VM regardless of the block timestamp.
          Usefull for creating a new block for a specific VM.
          '''

        vm_class = self.get_vm_class_for_block_timestamp(timestamp)
        self.vm_configuration = ((0, vm_class),)
        self.reinitialize()


    def get_vm_class_for_block_timestamp(self, timestamp: int = None) -> Type['BaseVM']:
        """
        Returns the VM class for the given block number.
        """
        if timestamp is None:
            timestamp = int(time.time())
        if self.vm_configuration is None:
            raise AttributeError("Chain classes must define the VMs in vm_configuration")
        validate_uint256(timestamp)
        for start_timestamp, vm_class in reversed(self.vm_configuration):
            if timestamp >= start_timestamp:
                return vm_class
        else:
            raise VMNotFound("No vm available for timestamp #{0}".format(timestamp))




