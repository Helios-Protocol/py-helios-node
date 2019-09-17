from hvm.chains.testnet import TestnetTesterChain
from hvm.vm.forks.photon import PhotonVM
from hvm.vm.forks.photon.transactions import PhotonTransaction
from eth_keys import keys
import pytest
from hvm.constants import random_private_keys
from hvm.constants import ZERO_HASH32, ZERO_ADDRESS

from eth_utils import int_to_big_endian, to_bytes

import random
from random import randint

def get_primary_node_private_helios_key(instance_number=0):
    return keys.PrivateKey(random_private_keys[instance_number])

def get_random_bytes(byte_length = 32):
    return to_bytes(random.getrandbits(byte_length*8*2))[:byte_length]

def create_random_photon_transaction(computation_call: bool = False) -> PhotonTransaction:
    key = get_primary_node_private_helios_key(randint(0,10))

    if computation_call:
        tx = PhotonTransaction(nonce=randint(0, 10000),
                               gas_price=randint(0, 10000),
                               gas=randint(0, 10000),
                               to=key.public_key.to_canonical_address(),
                               value=randint(0, 10000),
                               data=get_random_bytes(32),
                               caller=get_random_bytes(20),
                               origin=get_random_bytes(20),
                               code_address=get_random_bytes(20)
                               )

    else:
        tx = PhotonTransaction(nonce=randint(0, 10000),
                               gas_price=randint(0, 10000),
                               gas=randint(0, 10000),
                               to=key.public_key.to_canonical_address(),
                               value=randint(0, 10000),
                               data=get_random_bytes(32),
                               )
    return tx.get_signed(key,1)



