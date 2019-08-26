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
    fields = [
        ('nonce', f_big_endian_int),
        ('gas_price', big_endian_int),
        ('gas', f_big_endian_int),
        ('to', address),
        ('value', big_endian_int),
        ('data', binary),
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
            code_address = code_address,
            v = v,
            r = r,
            s = s,
        )

class PhotonReceiveTransaction(BosonReceiveTransaction):
    pass
    

