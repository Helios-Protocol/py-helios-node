from py_ecc import (
    optimized_bn128 as bn128,
)

from hvm import constants
from hvm.exceptions import (
    ValidationError,
    VMError,
)
from hvm.utils.bn128 import (
    validate_point,
)
from hvm.utils.numeric import (
    big_endian_to_int,
    int_to_big_endian,
)
from hvm.utils.padding import (
    pad32,
    pad32r,
)
from eth_utils.toolz import (
    curry,
)

from typing import TYPE_CHECKING, Tuple
if TYPE_CHECKING:
    from hvm.vm.forks.photon import PhotonComputation


@curry
def ecmul(
        computation: 'PhotonComputation',
        gas_cost: int = constants.GAS_ECMUL) -> 'PhotonComputation':

    computation.consume_gas(gas_cost, reason='ECMUL Precompile')

    try:
        result = _ecmull(computation.msg.data_as_bytes)
    except ValidationError:
        raise VMError("Invalid ECMUL parameters")

    result_x, result_y = result
    result_bytes = b''.join((
        pad32(int_to_big_endian(result_x.n)),
        pad32(int_to_big_endian(result_y.n)),
    ))
    computation.output = result_bytes
    return computation


def _ecmull(data: bytes) -> Tuple[bn128.FQ, bn128.FQ]:
    x_bytes = pad32r(data[:32])
    y_bytes = pad32r(data[32:64])
    m_bytes = pad32r(data[64:96])

    x = big_endian_to_int(x_bytes)
    y = big_endian_to_int(y_bytes)
    m = big_endian_to_int(m_bytes)

    p = validate_point(x, y)

    result = bn128.normalize(bn128.multiply(p, m))
    return result

