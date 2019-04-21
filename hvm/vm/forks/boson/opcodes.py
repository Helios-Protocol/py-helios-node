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

from hvm.vm.forks.helios_testnet.opcodes import HELIOS_TESTNET_OPCODES


BOSON_UPDATED_OPCODES = {

    #
    # Call
    #

}

BOSON_OPCODES = merge(
    copy.deepcopy(HELIOS_TESTNET_OPCODES),
    BOSON_UPDATED_OPCODES,
)




