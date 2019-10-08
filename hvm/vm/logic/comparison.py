from hvm import constants

from hvm.utils.numeric import (
    signed_to_unsigned,
    unsigned_to_signed,
)


def lt(computation):
    """
    Lesser Comparison
    """
    left, right = computation.stack_pop_ints(num_items=2)

    if left < right:
        result = 1
    else:
        result = 0

    computation.stack_push_int(result)


def gt(computation):
    """
    Greater Comparison
    """
    left, right = computation.stack_pop_ints(num_items=2)

    if left > right:
        result = 1
    else:
        result = 0

    computation.stack_push_int(result)


def slt(computation):
    """
    Signed Lesser Comparison
    """
    left, right = map(
        unsigned_to_signed,
        computation.stack_pop_ints(num_items=2),
    )

    if left < right:
        result = 1
    else:
        result = 0

    computation.stack_push_int(signed_to_unsigned(result))


def sgt(computation):
    """
    Signed Greater Comparison
    """
    left, right = map(
        unsigned_to_signed,
        computation.stack_pop_ints(num_items=2),
    )

    if left > right:
        result = 1
    else:
        result = 0

    computation.stack_push_int(signed_to_unsigned(result))


def eq(computation):
    """
    Equality
    """
    left, right = computation.stack_pop_ints(num_items=2)

    if left == right:
        result = 1
    else:
        result = 0

    computation.stack_push_int(result)


def iszero(computation):
    """
    Not
    """
    value = computation.stack_pop1_int()

    if value == 0:
        result = 1
    else:
        result = 0

    computation.stack_push_int(result)


def and_op(computation):
    """
    Bitwise And
    """
    left, right = computation.stack_pop_ints(num_items=2)

    result = left & right

    computation.stack_push_int(result)


def or_op(computation):
    """
    Bitwise Or
    """
    left, right = computation.stack_pop_ints(num_items=2)

    result = left | right

    computation.stack_push_int(result)


def xor(computation):
    """
    Bitwise XOr
    """
    left, right = computation.stack_pop_ints(num_items=2)

    result = left ^ right

    computation.stack_push_int(result)


def not_op(computation):
    """
    Not
    """
    value = computation.stack_pop1_int()

    result = constants.UINT_256_MAX - value

    computation.stack_push_int(result)


def byte_op(computation):
    """
    Bitwise And
    """
    position, value = computation.stack_pop_ints(num_items=2)

    if position >= 32:
        result = 0
    else:
        result = (value // pow(256, 31 - position)) % 256

    computation.stack_push_int(result)
