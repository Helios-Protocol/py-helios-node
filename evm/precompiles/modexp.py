from evm import constants

from evm.utils.numeric import (
    big_endian_to_int,
    get_highest_bit_index,
    int_to_big_endian,
)
from evm.utils.padding import (
    pad32r,
    zpad_right,
    zpad_left,
)


def _compute_adjusted_exponent_length(exponent_bytes):
    exponent_length = len(exponent_bytes)
    exponent = big_endian_to_int(exponent_bytes)

    if exponent_length <= 32 and exponent == 0:
        return 0
    elif exponent_length <= 32:
        return get_highest_bit_index(exponent)
    else:
        first_32_bytes_as_int = big_endian_to_int(exponent_bytes[:32])
        return (
            8 * (exponent_length - 32) +
            get_highest_bit_index(first_32_bytes_as_int)
        )


def _compute_complexity(modulus_length, base_length):
    complexity_anchor = max(modulus_length, base_length)

    # TODO: extract to function
    if complexity_anchor <= 64:
        return complexity_anchor ** 2
    elif complexity_anchor <= 1024:
        return (
            complexity_anchor ** 2 // 4 + 96 * complexity_anchor - 3072
        )
    else:
        return 2 ** 2 // 16 + 480 * complexity_anchor - 199680


def precompile_modexp(computation):
    """
    https://github.com/ethereum/EIPs/pull/198

    TODO: test against test vectors from EIP
    """
    # extract argument lengths
    base_length_bytes = pad32r(computation.msg.data[32:64])
    base_length = big_endian_to_int(base_length_bytes)

    exponent_length_bytes = pad32r(computation.msg.data[64:96])
    exponent_length = big_endian_to_int(exponent_length_bytes)

    modulus_length_bytes = pad32r(computation.msg.data[96:128])
    modulus_length = big_endian_to_int(modulus_length_bytes)

    # extract arguments
    base_end_idx = 128 + base_length
    base_bytes = zpad_right(computation.msg.data[128:base_end_idx], to_size=base_length)
    base = big_endian_to_int(base_bytes)

    exponent_end_idx = base_end_idx + exponent_length
    exponent_bytes = zpad_right(
        computation.msg.data[base_end_idx:exponent_end_idx],
        to_size=exponent_length,
    )
    exponent = big_endian_to_int(exponent_bytes)

    modulus_end_dx = exponent_end_idx + modulus_length
    modulus_bytes = zpad_right(
        computation.msg.data[exponent_end_idx:modulus_end_dx],
        to_size=modulus_length,
    )
    modulus = big_endian_to_int(modulus_bytes)

    # compute gas cost
    adjusted_exponent_length = _compute_adjusted_exponent_length(exponent_bytes)
    complexity = _compute_complexity(modulus_length, base_length)

    gas_fee = (
        complexity *
        max(adjusted_exponent_length, 1) //
        constants.GAS_MOD_EXP_QUADRATIC_DENOMINATOR
    )
    computation.gas_meter.consume_gas(gas_fee, reason='MODEXP Precompile')

    if modulus == 0:
        result = 0
    else:
        result = pow(base, exponent, modulus)

    result_bytes = zpad_left(int_to_big_endian(result), to_size=modulus_length)
    computation.output = result_bytes
    return computation
