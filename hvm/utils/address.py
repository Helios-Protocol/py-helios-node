import rlp_cython as rlp

from eth_hash.auto import keccak
from eth_typing import Address
from hvm.utils.numeric import int_to_bytes32


def force_bytes_to_address(value: bytes) -> Address:
    trimmed_value = value[-20:]
    padded_value = trimmed_value.rjust(20, b'\x00')
    return padded_value


def generate_contract_address(address: bytes, nonce: bytes) -> Address:
    return keccak(rlp.encode([address, nonce]))[-20:]

def generate_safe_contract_address(address: Address,
                                   salt: int,
                                   call_data: bytes) -> Address:
    return force_bytes_to_address(
        keccak(b'\xff' + address + int_to_bytes32(salt) + keccak(call_data))
    )