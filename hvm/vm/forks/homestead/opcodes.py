import copy

from cytoolz import merge

from hvm import constants
from hvm.vm import mnemonics
from hvm.vm import opcode_values
from hvm.vm.logic import (
    call,
)

from hvm.vm.forks.frontier.opcodes import FRONTIER_OPCODES


NEW_OPCODES = {
    opcode_values.DELEGATECALL: call.DelegateCall.configure(
        __name__='opcode:DELEGATECALL',
        mnemonic=mnemonics.DELEGATECALL,
        gas_cost=constants.GAS_CALL,
    )(),
}


HOMESTEAD_OPCODES = merge(
    copy.deepcopy(FRONTIER_OPCODES),
    NEW_OPCODES
)
