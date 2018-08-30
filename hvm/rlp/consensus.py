from abc import (
    ABCMeta,
    abstractmethod
)

import itertools

import rlp
from rlp.sedes import (
    big_endian_int,
    CountableList,
    binary,
)

from hvm.rlp.sedes import (
    hash32,   
    address,     
)

from eth_typing import (
    Hash32,
)

from eth_bloom import BloomFilter

from hvm.exceptions import ValidationError

from .sedes import (
    int256,
    int32,
)

from hvm.rlp.blocks import BaseBlock

from .logs import Log

from typing import Iterable

#
#fields = [
#    ('chain_address', address),
#    ('block_number', big_endian_int),
#    ('block_root', trie_root),
#    ('blocks', CountableList(BaseBlock)),
#]  
    
    
class BaseBlockConflictMessage(rlp.Serializable, metaclass=ABCMeta):
    pass