import functools
import itertools
import math

from evm.constants import (
    UINT_255_MAX,
    UINT_256_MAX,
    UINT_256_CEILING,
)


def int_to_big_endian(value: int) -> bytes:
    byte_length = math.ceil(value.bit_length() / 8)
    return (value).to_bytes(byte_length, byteorder='big')


def big_endian_to_int(value: bytes) -> int:
    return int.from_bytes(value, byteorder='big')


def int_to_bytes32(value):
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(
            "Value must be an integer: Got: {0}".format(
                type(value),
            )
        )
    if value < 0:
        raise ValueError(
            "Value cannot be negative: Got: {0}".format(
                value,
            )
        )
    if value > UINT_256_MAX:
        raise ValueError(
            "Value exeeds maximum UINT256 size.  Got: {0}".format(
                value,
            )
        )
    value_bytes = value.to_bytes(32, 'big')
    return value_bytes


def ceilXX(value: int, ceiling: int) -> int:
    remainder = value % ceiling
    if remainder == 0:
        return value
    else:
        return value + ceiling - remainder


ceil32 = functools.partial(ceilXX, ceiling=32)
ceil8 = functools.partial(ceilXX, ceiling=8)


def unsigned_to_signed(value):
    if value <= UINT_255_MAX:
        return value
    else:
        return value - UINT_256_CEILING


def signed_to_unsigned(value):
    if value < 0:
        return value + UINT_256_CEILING
    else:
        return value


def is_even(value: int) -> bool:
    return value % 2 == 0


def is_odd(value: int) -> bool:
    return value % 2 == 1


def get_highest_bit_index(value):
    value >>= 1
    for bit_length in itertools.count():
        if not value:
            return bit_length
        value >>= 1

def effecient_diff(list_1, list_2):
    '''
    returns a list that contains the elements in list_2 that are not in list_1
    '''
    if isinstance(list_1, set):
        s = list_1
    else:   
        s = set(list_1)
    return [x for x in list_2 if x not in s]

def are_items_in_list_equal(input_list):
    '''
    returns true if everything in the list is the same
    '''
    return not input_list or input_list.count(input_list[0]) == len(input_list)

def stake_weighted_average(item_stake_list):
    '''
    takes in a list of [[item, stake], [item, stake], ...]
    '''
    numerator = 0
    denominator = 0
    for item_stake in item_stake_list:
        numerator += item_stake[0]*item_stake[1]
        denominator += item_stake[1]
        
    return numerator/denominator
    
    
    