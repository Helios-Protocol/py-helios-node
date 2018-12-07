import difflib
from eth_hash.auto import keccak
from random import randint
from eth_utils import int_to_big_endian
import os
from pprint import pprint

from trie.constants import BLANK_HASH

from eth_typing import Hash32
from typing import List, Tuple, Set
import math
from itertools import zip_longest
import diff_match_patch as dmp_module
import time
from hvm.db.trie import BinaryTrie, HexaryTrie, _make_trie_root_and_nodes
from hvm.constants import BLANK_ROOT_HASH
from hvm.db.trie import make_binary_trie_root
from hvm.db.backends.memory import MemoryDB
import rlp
from eth_utils import encode_hex
from trie import BinaryTrie

# num_bytes = 4
# num_bits = num_bytes*8
# num_differences = 1000*10
#
# print(1- ((2**num_bits-1)/(2**num_bits))**num_differences)
# #
#
# num_bytes_per_hash = 1
#
# node_1_num_blocks = 1000
#
# node_1_chronological_block_hashes = []
#
# for i in range(node_1_num_blocks):
#     node_1_chronological_block_hashes.append(keccak(b"\x00"+os.urandom(12)+b"\x00"))
#
# print(make_binary_trie_root(node_1_chronological_block_hashes))
# root, _ = _make_trie_root_and_nodes(tuple(node_1_chronological_block_hashes))
# print(root)

test = [0,1,2,3,4,5]
print(test[2:10])