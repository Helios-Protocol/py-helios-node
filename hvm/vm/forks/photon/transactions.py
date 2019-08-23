
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

class PhotonReceiveTransaction(BosonReceiveTransaction):
    pass
    

