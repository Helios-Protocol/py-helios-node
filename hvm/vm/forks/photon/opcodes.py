import copy
import functools

from hvm.vm import opcode_values
from hvm.vm import mnemonics
from hvm import constants

from hvm.vm.forks.photon.constants import (
    GAS_SLOAD_EIP150,
    GAS_SELFDESTRUCT_EIP150,
    GAS_EXTCODEHASH_EIP1052,
    GAS_EXTCODEHASH_EIP1884,
    GAS_BALANCE_EIP1884,
    GAS_SLOAD_EIP1884
)

from hvm.vm.logic.storage import sstore_photon, sload_photon
from hvm.vm.logic.system import _selfdestruct, selfdestruct_photon
from hvm.vm.logic import arithmetic, context, system

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



    # New opcodes
    opcode_values.SHL: as_opcode(
        logic_fn=arithmetic.shl,
        mnemonic=mnemonics.SHL,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SHR: as_opcode(
        logic_fn=arithmetic.shr,
        mnemonic=mnemonics.SHR,
        gas_cost=constants.GAS_VERYLOW,
    ),
    opcode_values.SAR: as_opcode(
        logic_fn=arithmetic.sar,
        mnemonic=mnemonics.SAR,
        gas_cost=constants.GAS_VERYLOW,
    ),

    # opcode_values.CREATE2: system.Create2.configure(
    #     __name__='opcode:CREATE2',
    #     mnemonic=mnemonics.CREATE2,
    #     gas_cost=constants.GAS_CREATE,
    # )(),

    opcode_values.CHAINID: as_opcode(
        logic_fn=context.chain_id,
        mnemonic=mnemonics.CHAINID,
        gas_cost=constants.GAS_BASE,
    ),
    opcode_values.SELFBALANCE: as_opcode(
        logic_fn=context.selfbalance,
        mnemonic=mnemonics.SELFBALANCE,
        gas_cost=constants.GAS_LOW,
    ),

    # Repriced opcodes
    opcode_values.BALANCE: as_opcode(
        logic_fn=context.balance,
        mnemonic=mnemonics.BALANCE,
        gas_cost=GAS_BALANCE_EIP1884,
    ),
    opcode_values.EXTCODEHASH: as_opcode(
        logic_fn=context.extcodehash,
        mnemonic=mnemonics.EXTCODEHASH,
        gas_cost=GAS_EXTCODEHASH_EIP1884,
    ),
    opcode_values.SSTORE: as_opcode(
        logic_fn=ensure_no_static(sstore_photon),
        mnemonic=mnemonics.SSTORE,
        gas_cost=constants.GAS_NULL,
    ),
    opcode_values.SLOAD: as_opcode(
        logic_fn=sload_photon,
        mnemonic=mnemonics.SLOAD,
        gas_cost=GAS_SLOAD_EIP1884,
    ),
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




