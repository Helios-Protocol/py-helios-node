import functools

from eth_typing import Address
from eth_utils import int_to_big_endian
from hvm.constants import GAS_TX, CREATE_CONTRACT_ADDRESS, GAS_TXCREATE, GAS_TXDATAZERO, GAS_TXDATANONZERO
from hvm.exceptions import ValidationError
from hvm.vm.forks.boson import BosonTransaction, BosonReceiveTransaction
from rlp_cython.sedes import (
    big_endian_int,
    binary,
    f_big_endian_int,
    boolean
)
from hvm.rlp.sedes import (
    address,
)

import rlp_cython as rlp

class PhotonTransaction(BosonTransaction):
    '''
    caller:
    # If the tx was created in a computation on a smart contract chain, caller is the address of that chain.
    # In that case, sender can be anyone who created the block.
    # TODO: Add functions to this that override sender to caller if it is not null. Then create new property called
    # signer, which points to old sender. This will allow the vm to transfer value properly.

    origin:
    # origin is the address of the account that started the chain of smart contract computations that resulted in
    # this transaction. It points to the same thing tx.origin does in classic solidity.
    # This is null if this tx wasn't created by a smart contract.
    # Add validation that makes sure this is null if it didnt come from a smart contract.
    '''
    fields = [
        ('nonce', f_big_endian_int),
        ('gas_price', big_endian_int),
        ('gas', f_big_endian_int),
        ('to', address),
        ('value', big_endian_int),
        ('data', binary),
        ('caller', address),
        ('origin', address),
        ('code_address', address),
        ('create_address', address),
        ('execute_on_send', boolean),
        ('v', big_endian_int),
        ('r', big_endian_int),
        ('s', big_endian_int),
    ]

    def __init__(self,  # noqa: F811
                 nonce,
                 gas_price,
                 gas,
                 to,
                 value,
                 data = b'',
                 caller = b'',
                 origin = b'',
                 code_address = b'',
                 create_address = b'',
                 execute_on_send = False,
                 v=0,
                 r=0,
                 s=0,
                 **kwargs):

        super(PhotonTransaction, self).__init__(
            nonce = nonce,
            gas_price = gas_price,
            gas = gas,
            to = to,
            value = value,
            data = data,
            caller = caller,
            origin = origin,
            code_address = code_address,
            create_address = create_address,
            execute_on_send=execute_on_send,
            v = v,
            r = r,
            s = s,
            **kwargs
        )

    @property
    def created_by_computation(self) -> bool:
        return self.caller != b'' or self.origin != b'' or self.create_address != b''

    @property
    def refund_address(self) -> Address:
        if self.created_by_computation:
            return self.origin
        else:
            return self.sender

    @property
    def is_create(self) -> bool:
        return self.to == CREATE_CONTRACT_ADDRESS or self.create_address != b''

    def validate(self):
        if self.is_create:
            if self.execute_on_send:
                raise ValidationError("Create transactions are not allowed to execute on send.")

        super(PhotonTransaction, self).validate()

    def get_intrinsic_gas(self):
        return _get_photon_intrinsic_gas(self)


# This is a create


class PhotonReceiveTransaction(BosonReceiveTransaction):
    pass
    

def _get_photon_intrinsic_gas(transaction):
    num_zero_bytes = transaction.data.count(b'\x00')
    num_non_zero_bytes = len(transaction.data) - num_zero_bytes
    if transaction.is_create:
        create_cost = GAS_TXCREATE
    else:
        create_cost = 0
    return (
        GAS_TX +
        num_zero_bytes * GAS_TXDATAZERO +
        num_non_zero_bytes * GAS_TXDATANONZERO +
        create_cost
    )