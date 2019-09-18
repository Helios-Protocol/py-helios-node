import copy
import functools

from hvm.vm import opcode_values
from hvm.vm import mnemonics
from hvm import constants

from hvm.vm.forks.photon.constants import GAS_SLOAD_EIP150, GAS_SELFDESTRUCT_EIP150

from hvm.vm.logic.storage import sstore_photon, sload_photon
from hvm.vm.logic.system import _selfdestruct, selfdestruct_photon
from hvm.vm.opcode import as_opcode
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
    # Storage
    #

    opcode_values.SSTORE: as_opcode(
        logic_fn=ensure_no_static(sstore_photon),
        mnemonic=mnemonics.SSTORE,
        gas_cost=constants.GAS_NULL,
    ),
    opcode_values.SLOAD: as_opcode(
        logic_fn=sload_photon,
        mnemonic=mnemonics.SLOAD,
        gas_cost=GAS_SLOAD_EIP150,
    ),

    #
    # System
    #

    opcode_values.SELFDESTRUCT: as_opcode(
        logic_fn=ensure_no_static(selfdestruct_photon),
        mnemonic=mnemonics.SELFDESTRUCT,
        gas_cost=GAS_SELFDESTRUCT_EIP150,
    ),

}

PHOTON_OPCODES = merge(
    copy.deepcopy(BOSON_OPCODES),
    PHOTON_UPDATED_OPCODES,
)




