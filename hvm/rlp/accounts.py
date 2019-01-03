import rlp_cython as rlp
from rlp_cython.sedes import (
    big_endian_int,
    CountableList,
)

from hvm.constants import (
    EMPTY_SHA3,
    BLANK_ROOT_HASH,
    ZERO_ADDRESS,
)

from .sedes import (
    trie_root,
    hash32,
    address
    
)
from eth_typing import Address


from typing import Any


class TransactionKey(rlp.Serializable):
    fields = [
        ('transaction_hash', hash32),
        ('sender_block_hash', hash32),
    ]

 
class BlockConflictKey(rlp.Serializable):
    fields = [
        ('slash_block_hash', hash32),
        ('conflict_block_number', big_endian_int),
    ]  
    
class Account(rlp.Serializable):
    """
    RLP object for accounts.
    """
    fields = [
        ('nonce', big_endian_int),
        ('block_number', big_endian_int),
        ('receivable_transactions', CountableList(TransactionKey)),
        ('block_conflicts', CountableList(BlockConflictKey)),
        ('balance', big_endian_int),
        ('storage_root', trie_root),
        ('code_hash', hash32)
    ]

    def __init__(self,
                 nonce: int=0,
                 block_number: int=0,
                 receivable_transactions = (),
                 block_conflicts = (),
                 balance: int=0,
                 storage_root: bytes=BLANK_ROOT_HASH,
                 code_hash: bytes=EMPTY_SHA3,
                 **kwargs: Any) -> None:
        super(Account, self).__init__(nonce, block_number, receivable_transactions, block_conflicts, balance, storage_root, code_hash, **kwargs)
