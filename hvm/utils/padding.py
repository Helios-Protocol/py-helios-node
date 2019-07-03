from cytoolz import (
    curry,
)

from typing import List
from sortedcontainers import SortedDict

ZERO_BYTE = b'\x00'

import math

@curry
def zpad_right(value: bytes, to_size: int) -> bytes:
    return value.ljust(to_size, ZERO_BYTE)


@curry
def zpad_left(value: bytes, to_size: int) -> bytes:
    return value.rjust(to_size, ZERO_BYTE)


pad32 = zpad_left(to_size=32)
pad32r = zpad_right(to_size=32)

def de_sparse_timestamp_item_list(sparse_list, spacing, filler = None, end_timestamp = None):
    if len(sparse_list) <= 1 and end_timestamp is None:
        return sparse_list

    sparse_dict = SortedDict(sparse_list)

    timestamps = list(sparse_dict.keys())

    start_timestamp = timestamps[0]
    if end_timestamp is None:
        end_timestamp = timestamps[-1]
    
    expected_length = (end_timestamp-start_timestamp)/spacing + abs(spacing)
    
    if len(sparse_list) == expected_length:
        return sparse_list

    for timestamp in range(start_timestamp, end_timestamp+spacing, spacing):
        if timestamp not in sparse_dict:
            if filler is not None:
                sparse_dict[timestamp] = filler
            else:
                sparse_dict[timestamp] = sparse_dict[timestamp-spacing]
            
    
    return list(sparse_dict.items())


def propogate_timestamp_item_list_to_present(initial_list: List, spacing: int, end_timestamp: int):
    if len(initial_list) == 0:
        return initial_list

    initial_dict = SortedDict(initial_list)

    timestamps = list(initial_dict.keys())

    last_timestamp = timestamps[-1]
    if last_timestamp >= end_timestamp:
        return initial_list

    iter_start_timestamp = last_timestamp + spacing
    iter_end_timestamp = end_timestamp + spacing

    filler = initial_dict[last_timestamp]

    for timestamp in range(iter_start_timestamp, iter_end_timestamp, spacing):
        initial_dict[timestamp] = filler

    return list(initial_dict.items())
