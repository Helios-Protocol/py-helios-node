import functools
from typing import Dict, List, Tuple, Union

import rlp_cython as rlp
from trie import (
    HexaryTrie,
)
from trie import BinaryTrie as ParentBinaryTrie

from hvm.constants import (
    BLANK_ROOT_HASH,
)
from trie.binary import parse_node
from trie.constants import (
    BLANK_HASH,
    KV_TYPE,
    BRANCH_TYPE,
    LEAF_TYPE,
    BYTE_0,
    BYTE_1,
)
from hvm.rlp.receipts import Receipt
from hvm.rlp.transactions import BaseTransaction
from eth_hash.auto import keccak
import os
from eth_typing import Hash32

from hvm.rlp.sedes import hash32

def make_trie_root_and_nodes(
        items: Union[List[Receipt], List[BaseTransaction]]) -> Tuple[bytes, Dict[bytes, bytes]]:
    return _make_trie_root_and_nodes(tuple(rlp.encode(item) for item in items))

# This cache is expected to be useful when importing blocks as we call this once when importing
# and again when validating the imported block. But it should also help for post-Byzantium blocks
# as it's common for them to have duplicate receipt_roots. Given that, it probably makes sense to
# use a relatively small cache size here.
@functools.lru_cache(128)
def _make_trie_root_and_nodes(items: Tuple[bytes, ...]) -> Tuple[bytes, Dict[bytes, bytes]]:
    kv_store = {}  # type: Dict[bytes, bytes]
    trie = HexaryTrie(kv_store, BLANK_ROOT_HASH)
    with trie.squash_changes() as memory_trie:
        for index, item in enumerate(items):
            index_key = rlp.encode(index, sedes=rlp.sedes.big_endian_int)
            memory_trie[index_key] = item
    return trie.root_hash, kv_store



class BinaryTrie(ParentBinaryTrie):
    def get_leaf_nodes(self, node, reverse = False):
        """
        This gets the leaf nodes from left to right
        """
        node_type, left, right = parse_node(self.db[node])
        #print('node_type {}'.format(node_type))
        if node_type == KV_TYPE:
            #print("BRANCH KEY:{}".format(decode_from_bin(left)))
            yield from self.get_leaf_nodes(right, reverse)
        elif node_type == BRANCH_TYPE:
            if reverse:
                yield from self.get_leaf_nodes(right, reverse)
                yield from self.get_leaf_nodes(left, reverse)
            else:
                yield from self.get_leaf_nodes(left, reverse)
                yield from self.get_leaf_nodes(right, reverse)
        else:
            yield right

#this is probably unreliable because some keys are prefixes of other keys...
def make_binary_trie_root(items: Tuple[bytes, ...]) -> bytes:
    kv_store = {}  # type: Dict[bytes, bytes]
    trie = BinaryTrie(kv_store, BLANK_HASH)

    for index, item in enumerate(items):
        index_key = rlp.encode(index, sedes=rlp.sedes.big_endian_int)
        trie[index_key] = item

    return trie.root_hash


