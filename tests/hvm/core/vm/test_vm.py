from hvm.chains.testnet import TestnetTesterChain
from hvm.vm.forks.photon import PhotonVM
from hvm.vm.forks.photon.transactions import PhotonTransaction
from eth_keys import keys
import pytest
from hvm.constants import random_private_keys
from hvm.exceptions import ValidationError
from hvm.constants import ZERO_HASH32, ZERO_ADDRESS
def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(random_private_keys[instance_number])

from hvm.db.backends.memory import MemoryDB

from hvm.chains.testnet.constants import PHOTON_TIMESTAMP

from tests.test_utils import create_random_photon_transaction

from hvm.vm.forks.photon.blocks import PhotonBlock
import time

def test_photon_vm_contains_computation_calls():
    key_0 = get_primary_node_private_helios_key(0)

    testdb1 = MemoryDB()

    chain = TestnetTesterChain(testdb1, key_0.public_key.to_canonical_address(), key_0)

    photon_vm = chain.get_vm(timestamp=PHOTON_TIMESTAMP)

    rand_normal_tx = [create_random_photon_transaction() for i in range(10)]
    rand_computation_call_tx = [create_random_photon_transaction(True) for i in range(100)]
    mix_tx = rand_normal_tx.copy()
    mix_tx.extend(rand_computation_call_tx)

    assert(photon_vm.contains_computation_calls(rand_normal_tx) == False)
    assert(photon_vm.contains_computation_calls(rand_computation_call_tx) == True)
    assert(photon_vm.contains_computation_calls(mix_tx) == True)


def test_separate_normal_transactions_and_computation_calls():
    key_0 = get_primary_node_private_helios_key(0)

    testdb1 = MemoryDB()

    chain = TestnetTesterChain(testdb1, key_0.public_key.to_canonical_address(), key_0)

    photon_vm = chain.get_vm(timestamp=PHOTON_TIMESTAMP)

    rand_normal_tx = [create_random_photon_transaction() for i in range(10)]
    rand_computation_call_tx = [create_random_photon_transaction(True) for i in range(10)]
    mix_tx = rand_normal_tx.copy()
    mix_tx.extend(rand_computation_call_tx)

    sep_normal, sep_comp = photon_vm.separate_normal_transactions_and_computation_calls(mix_tx)

    assert(sep_normal == rand_normal_tx)
    assert(sep_comp == rand_computation_call_tx)

    with pytest.raises(ValidationError):
        mix_tx.extend(rand_normal_tx)
        photon_vm.separate_normal_transactions_and_computation_calls(mix_tx)


def test_get_next_nonce_after_normal_transactions():
    key_0 = get_primary_node_private_helios_key(0)

    testdb1 = MemoryDB()

    chain = TestnetTesterChain(testdb1, key_0.public_key.to_canonical_address(), key_0)

    photon_vm = chain.get_vm(timestamp=PHOTON_TIMESTAMP)

    rand_normal_tx = [create_random_photon_transaction() for i in range(10)]
    rand_computation_call_tx = [create_random_photon_transaction(True) for i in range(100)]
    mix_tx = rand_normal_tx.copy()
    mix_tx.extend(rand_computation_call_tx)

    expected_nonce = rand_normal_tx[-1].nonce +1
    assert(photon_vm.get_next_nonce_after_normal_transactions(rand_normal_tx) == expected_nonce)

    expected_nonce = rand_computation_call_tx[0].nonce
    assert (photon_vm.get_next_nonce_after_normal_transactions(rand_computation_call_tx) == expected_nonce)

    expected_nonce = rand_normal_tx[-1].nonce +1
    assert (photon_vm.get_next_nonce_after_normal_transactions(mix_tx) == expected_nonce)

def test_validate_computation_call_send_transactions_against_block():
    key_0 = get_primary_node_private_helios_key(0)
    key_1 = get_primary_node_private_helios_key(0)

    testdb1 = MemoryDB()

    chain = TestnetTesterChain(testdb1, key_0.public_key.to_canonical_address(), key_0)

    photon_vm = chain.get_vm(timestamp=PHOTON_TIMESTAMP)

    rand_normal_tx = [create_random_photon_transaction() for i in range(10)]
    rand_computation_call_tx = [create_random_photon_transaction(True) for i in range(100)]
    rand_computation_call_tx_2 = [create_random_photon_transaction(True) for i in range(100)]
    mix_tx = rand_normal_tx.copy()
    mix_tx.extend(rand_computation_call_tx)
    re_signed_rand_computation_call_tx = [tx.get_signed(key_1, 1) for tx in rand_computation_call_tx]

    out_of_order_tx = rand_computation_call_tx.copy()
    out_of_order_tx.extend(rand_normal_tx)

    base_block = chain.get_block()
    block_1 = base_block.copy(transactions=mix_tx)
    block_out_of_order = base_block.copy(transactions=out_of_order_tx)
    block_normal_tx = base_block.copy(transactions=rand_normal_tx)
    
    photon_vm.validate_computation_call_send_transactions_against_block(block_1, rand_computation_call_tx)
    photon_vm.validate_computation_call_send_transactions_against_block(block_1, re_signed_rand_computation_call_tx)
    photon_vm.validate_computation_call_send_transactions_against_block(block_normal_tx, [])

    with pytest.raises(ValidationError):
        photon_vm.validate_computation_call_send_transactions_against_block(block_normal_tx, re_signed_rand_computation_call_tx)
    with pytest.raises(ValidationError):
        photon_vm.validate_computation_call_send_transactions_against_block(block_1, rand_computation_call_tx_2)
    with pytest.raises(ValidationError):
        photon_vm.validate_computation_call_send_transactions_against_block(block_out_of_order, rand_computation_call_tx_2)
    with pytest.raises(ValidationError):
        photon_vm.validate_computation_call_send_transactions_against_block(block_out_of_order, out_of_order_tx)


#test_photon_vm_contains_computation_calls()
#test_separate_normal_transactions_and_computation_calls()
#test_get_next_nonce_after_normal_transactions()
#test_validate_computation_call_send_transactions_against_block()