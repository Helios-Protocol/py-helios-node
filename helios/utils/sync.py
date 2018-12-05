import difflib
from eth_hash.auto import keccak
from random import randint
from eth_utils import int_to_big_endian
import os
from eth_typing import Hash32
from typing import List, Tuple, Set
import math
import time
from hvm.types import Timestamp

def grouper(iterable, n):
    args = [iter(iterable)] * n
    return zip(*args)

def prepare_hash_fragments(hashes: List[Hash32], num_bytes: int) -> List[bytes]:
    fragment_list = []
    for hash in hashes:
        fragment_list.append(hash[0:num_bytes])
    return fragment_list

def get_missing_hash_locations_bytes(our_hash_fragments: bytes, their_hash_fragments: bytes, num_bytes: int) -> Tuple[Set[int], Set[int]]:
    our_hash_fragments_list = grouper(our_hash_fragments, num_bytes)
    their_hash_fragments_list = grouper(their_hash_fragments, num_bytes)
    return get_missing_hash_locations_list(our_hash_fragments_list, their_hash_fragments_list)

def get_missing_hash_locations_list(our_hash_fragments: List[bytes], their_hash_fragments: List[bytes]) -> Tuple[Set[int], Set[int]]:
    s = difflib.SequenceMatcher(None, our_hash_fragments, their_hash_fragments, autojunk=False)

    hash_positions_of_theirs_that_we_need = set()
    hash_positions_of_ours_that_they_need = set()

    # this will tell us what needs to be done to turn our_hash_identifier into their_hash_identifier.
    # if it says we need to insert, then it is a group of hashes that they have that we don't
    # if it says we need to delete, then it is a group of hashes that we have that they don't
    for tag, i1, i2, j1, j2 in s.get_opcodes():
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

    return hash_positions_of_theirs_that_we_need, hash_positions_of_ours_that_they_need

