from rlp_cython.sedes import (
    BigEndianInt,
    Binary,
)

from hvm.constants import (
    COLLATION_SIZE,
)


address = Binary.fixed_length(20, allow_empty=True)
collation_body = Binary.fixed_length(COLLATION_SIZE)
hash32 = Binary.fixed_length(32)
int32 = BigEndianInt(32)
int256 = BigEndianInt(256)
trie_root = Binary.fixed_length(32, allow_empty=True)



