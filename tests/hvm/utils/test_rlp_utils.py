#from hvm.utils.rlp import ensure_rlp_objects_are_equal_except_for_field_names
from hvm.vm.forks.photon.utils import ensure_computation_call_send_transactions_are_equal
from hvm.vm.forks.photon.transactions import PhotonTransaction
from hvm.constants import random_private_keys
from eth_keys import keys
import pytest
from hvm.exceptions import ValidationError
from hvm.constants import ZERO_HASH32, ZERO_ADDRESS
def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(random_private_keys[instance_number])


def test_ensure_computation_call_send_transactions_are_equal():
    key_0 = get_primary_node_private_helios_key(0)
    key_1 = get_primary_node_private_helios_key(1)

    tx_0 = PhotonTransaction(nonce=10,
                             gas_price=20,
                             gas = 30,
                             to = key_0.public_key.to_canonical_address(),
                             value = 40,
                             data = ZERO_HASH32,
                             caller = ZERO_ADDRESS,
                             origin = ZERO_ADDRESS,
                             code_address = ZERO_ADDRESS
                             )

    one_address = 20 * b'\x01'
    one_hash = 32 * b'\x01'

    tx_1 = PhotonTransaction(nonce=20,
                             gas_price=30,
                             gas=40,
                             to=key_1.public_key.to_canonical_address(),
                             value=50,
                             data=one_hash,
                             caller=one_address,
                             origin=one_address,
                             code_address=one_address
                             )

    tx_0 = tx_0.get_signed(key_0, 1)
    tx_0_different_sig = tx_0.get_signed(key_1, 1)
    tx_1 = tx_1.get_signed(key_1,1)

    ensure_computation_call_send_transactions_are_equal(tx_0, tx_0)
    ensure_computation_call_send_transactions_are_equal(tx_0, tx_0_different_sig)

    with pytest.raises(ValidationError):
        ensure_computation_call_send_transactions_are_equal(tx_0, tx_1)

# test_ensure_computation_call_send_transactions_are_equal()
# exit()