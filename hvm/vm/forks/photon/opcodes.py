import copy
import functools

from cytoolz import merge

from hvm.exceptions import (
    WriteProtection,
)

def ensure_no_static(opcode_fn):
    @functools.wraps(opcode_fn)
    def inner(computation):
        if computation.msg.is_static:
            raise WriteProtection("Cannot modify state while inside of a STATICCALL context")
        return opcode_fn(computation)
    return inner

from hvm.vm.forks.boson.opcodes import BOSON_OPCODES


PHOTON_UPDATED_OPCODES = {

    #
    # Call
    #

}

PHOTON_OPCODES = merge(
    copy.deepcopy(BOSON_OPCODES),
    PHOTON_UPDATED_OPCODES,
)




