import rlp
from rlp import sedes
from evm.rlp.sedes import (
    address,
    hash32,    
    trie_root,
)

from evm.rlp.headers import BlockHeader
from evm.rlp.transactions import BaseTransaction


# This is needed because BaseTransaction has several @abstractmethods, which means it can't be
# instantiated.
class P2PTransaction(rlp.Serializable):
    fields = BaseTransaction._meta.fields


class BlockBody(rlp.Serializable):
    fields = [
        ('transactions', sedes.CountableList(P2PTransaction)),
        ('uncles', sedes.CountableList(BlockHeader))
    ]

class BlockNumberKey(rlp.Serializable):
    fields = [
        ('wallet_address', address),
        ('block_number', sedes.big_endian_int)
    ]
    
class BlockHashKey(rlp.Serializable):
    fields = [
        ('wallet_address', address),
        ('block_number', sedes.big_endian_int),
        ('block_hash', hash32)
    ]
    
class TimestampRootHashKey(rlp.Serializable):
    fields = [
        ('timestamp', sedes.big_endian_int),
        ('root_hash', trie_root),
    ]
    
    