from evm.rlp.consensus import BaseBlockConflictMessage 
from rlp.sedes import (
     big_endian_int,
     CountableList,
)
from evm.rlp.sedes import (
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