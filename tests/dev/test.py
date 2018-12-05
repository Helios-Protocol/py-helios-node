import difflib
from eth_hash.auto import keccak
from random import randint
from eth_utils import int_to_big_endian
import os
from pprint import pprint
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

# num_bytes = 4
# num_bits = num_bytes*8
# num_differences = 1000*10
#
# print(1- ((2**num_bits-1)/(2**num_bits))**num_differences)
#
# exit()
#
# dmp = dmp_module.diff_match_patch()
# diff = dmp.diff_main(b'12564564535', b'12345654564564564', checklines = False)
# print(diff)
#
# exit()


def prepare_identifying_bytestring(hashes: List[Hash32], num_bytes: int) -> bytes:
    bytes_out = bytearray()
    for hash in hashes:
        bytes_out.extend(hash[0:num_bytes])
    return bytes(bytes_out)


def get_missing_hash_locations_list(our_hash_identifier: List[bytes], their_hash_identifier: List[bytes]) -> Tuple[Set[int], Set[int]]:
    s = difflib.SequenceMatcher(None, our_hash_identifier, their_hash_identifier, autojunk=False)

    hash_positions_of_theirs_that_we_need = set()
    hash_positions_of_ours_that_they_need = set()

    last_i2 = 0
    last_j2 = 0
    # this will tell us what needs to be done to turn our_hash_identifier into their_hash_identifier.
    # if it says we need to insert, then it is a group of hashes that they have that we don't
    # if it says we need to delete, then it is a group of hashes that we have that they don't
    for tag, i1, i2, j1, j2 in s.get_opcodes():
        # print('{:7}   a[{}:{}] --> b[{}:{}] {!r:>8} --> {!r}'.format(
        #         tag, i1, i2, j1, j2, our_hash_identifier[i1:i2], their_hash_identifier[j1:j2]))

        if tag == 'insert':
            for i in range(j1, j2):
                # in this case, with list inputs, i is actually the index of the hash
                hash_position = i
                hash_positions_of_theirs_that_we_need.add(hash_position)
                #we will get duplicates often, but we are using a set, so they won't duplicate.

        elif tag == 'delete':
            for i in range(i1, i2):
                # in this case, with list inputs, i is actually the index of the hash
                hash_position = i
                hash_positions_of_ours_that_they_need.add(hash_position)
                #we will get duplicates often, but we are using a set, so they won't duplicate.

        #in this case, we have one they don't, and they have one we don't
        elif tag == 'replace':
            for i in range(j1, j2):
                # in this case, with list inputs, i is actually the index of the hash
                hash_position = i
                hash_positions_of_theirs_that_we_need.add(hash_position)
                #we will get duplicates often, but we are using a set, so they won't duplicate.

            for i in range(i1, i2):
                # in this case, with list inputs, i is actually the index of the hash
                hash_position = i
                hash_positions_of_ours_that_they_need.add(hash_position)
                #we will get duplicates often, but we are using a set, so they won't duplicate.
        elif tag == 'equal':
            assert(our_hash_identifier[i1:i2] == their_hash_identifier[j1:j2])

        assert(i1 == last_i2), 'last_i2'
        assert(j1 == last_j2), 'last_i2'
        last_i2 = i2
        last_j2 = j2


    return hash_positions_of_theirs_that_we_need, hash_positions_of_ours_that_they_need


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    #return zip_longest(*args, fillvalue=fillvalue)
    return zip(*args)


# def verify_diff_correctness(our_block_hashes: List[Hash32], hash_positions_of_theirs_that_we_need: Iterable)

num_bytes_per_hash = 1

node_1_num_blocks = 1000
node_2_new_blocks = 200
node_2_missing_blocks = 200


node_1_chronological_block_hashes = []


for i in range(node_1_num_blocks):
    node_1_chronological_block_hashes.append(keccak(b"\x00"+os.urandom(12)+b"\x00"))

node_2_chronological_block_hashes = list(node_1_chronological_block_hashes)

node_1_root_hash, _ = _make_trie_root_and_nodes(tuple(node_2_chronological_block_hashes))

#delete some that node 2 is missing
for i in range(node_2_missing_blocks):
    del(node_2_chronological_block_hashes[randint(0,len(node_2_chronological_block_hashes)-1)])


#add additional blocks that node 2 has that node 1 doesnt
for i in range(node_2_new_blocks):
    node_2_chronological_block_hashes.insert(randint(0,len(node_2_chronological_block_hashes)-1), keccak(b"\x00"+os.urandom(12)+b"\x00"))


# for hash in node_1_chronological_block_hashes:
#     print(hash)
# print()

print('a')

node_1_ident = prepare_identifying_bytestring(node_1_chronological_block_hashes, num_bytes_per_hash)
node_2_ident = prepare_identifying_bytestring(node_2_chronological_block_hashes, num_bytes_per_hash)

# start_time = time.time()
# dmp = dmp_module.diff_match_patch()
# diff = dmp.diff_main(node_1_ident, node_2_ident, checklines = False)
#
# print('google took {}'.format(time.time()-start_time))

# start_time = time.time()
# a, b = get_missing_hash_locations(node_1_ident, node_2_ident, num_bytes_per_hash)
#
# print('python string took {}'.format(time.time()-start_time))

node_1_list_ident = list(grouper(node_1_ident, num_bytes_per_hash))
node_2_list_ident = list(grouper(node_2_ident, num_bytes_per_hash))

# print(node_1_list_ident)
# print(node_2_list_ident)

start_time = time.time()
a, b = get_missing_hash_locations_list(node_1_list_ident, node_2_list_ident)

print(a)

print('python took {}'.format(time.time()-start_time))

#lets try to make them the same

node_1_chronological_block_hashes_final = list(node_1_chronological_block_hashes)
node_2_chronological_block_hashes_final = list(node_2_chronological_block_hashes)
for position in a:
    node_1_chronological_block_hashes_final.append(node_2_chronological_block_hashes[position])

print()

for position in b:
    node_2_chronological_block_hashes_final.append(node_1_chronological_block_hashes[position])

node_1_chronological_block_hashes_final.sort()
node_2_chronological_block_hashes_final.sort()


assert(node_1_chronological_block_hashes_final == node_2_chronological_block_hashes_final)



