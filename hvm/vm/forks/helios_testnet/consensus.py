from hvm.rlp.consensus import BaseBlockConflictMessage
from rlp_cython.sedes import (
     big_endian_int,
     CountableList,
)
from hvm.rlp.sedes import (
    trie_root,
    address        
)
from .blocks import (
    HeliosTestnetBlock,
)

class HeliosTestnetBlockConflictMessage(BaseBlockConflictMessage):
    fields = [
        ('chain_address', address),
        ('block_number', big_endian_int),
        ('block_root', trie_root),
        ('blocks', CountableList(HeliosTestnetBlock)),
    ]