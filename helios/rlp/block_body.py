import rlp
from rlp import sedes


from hvm.rlp.headers import BlockHeader
#from hvm.rlp.transactions import BaseTransactionFields


# class BlockBody(rlp.Serializable):
#     fields = [
#         ('transactions', sedes.CountableList(BaseTransactionFields)),
#         ('uncles', sedes.CountableList(BlockHeader))
#     ]
