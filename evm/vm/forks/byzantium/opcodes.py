import copy

from cytoolz import merge

from evm import constants
from evm import opcode_values
from evm import mnemonics

from evm.opcode import as_opcode

from evm.logic import (
    system,
    call,
)

from evm.vm.forks.spurious_dragon.opcodes import SPURIOUS_DRAGON_OPCODES


UPDATED_OPCODES = {
    opcode_values.REVERT: as_opcode(
        logic_fn=system.revert,
        mnemonic=mnemonics.REVERT,
        gas_cost=constants.GAS_ZERO,
    ),
    opcode_values.STATICCALL: call.StaticCall.configure(
        name='opcode:STATICCALL',
        mnemonic=mnemonics.STATICCALL,
        gas_cost=constants.GAS_CALL,
    ),
}


BYZANTIUM_OPCODES = merge(
    copy.deepcopy(SPURIOUS_DRAGON_OPCODES),
    UPDATED_OPCODES,
)
