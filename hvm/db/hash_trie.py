from eth_hash.auto import keccak

from hvm.db.keymap import (
    KeyMapDB,
)


class HashTrie(KeyMapDB):
    keymap = keccak
