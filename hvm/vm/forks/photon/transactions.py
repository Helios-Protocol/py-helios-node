from eth_typing import Address
from hvm.constants import GAS_TX
from hvm.vm.forks.boson import BosonTransaction, BosonReceiveTransaction
from rlp_cython.sedes import (
    big_endian_int,
    binary,
    f_big_endian_int,
)
from hvm.rlp.sedes import (
    address,
)

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
                 v=0,
                 r=0,
                 s=0):

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
            v = v,
            r = r,
            s = s,
        )

    @property
    def created_by_computation(self) -> bool:
        return self.caller != b'' or self.origin != b''

    @property
    def refund_address(self) -> Address:
        if self.created_by_computation:
            return self.origin
        else:
            return self.sender

class PhotonReceiveTransaction(BosonReceiveTransaction):
    pass
    

