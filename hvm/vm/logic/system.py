from eth_typing import Address
from hvm import constants
from hvm.constants import GAS_TX
from hvm.exceptions import (
    Halt,
    Revert,
    WriteProtection,
    ForbiddenOperationForSurrogateCall, DepreciatedVMFunctionality)

from hvm.utils.address import (
    force_bytes_to_address,
    generate_contract_address,
    generate_safe_contract_address)
from hvm.utils.hexadecimal import (
    encode_hex,
)
from hvm.utils.numeric import ceil32
from hvm.vm import mnemonics
from hvm.vm.message import Message

from hvm.vm.opcode import (
    Opcode,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hvm.vm.forks.photon import PhotonComputation

from .call import max_child_gas_eip150


def return_op(computation):
    start_position, size = computation.stack_pop_ints(num_items=2)

    computation.extend_memory(start_position, size)

    output = computation.memory_read(start_position, size)
    computation.output = bytes(output)
    raise Halt('RETURN')


def revert(computation):
    start_position, size = computation.stack_pop_ints(num_items=2)

    computation.extend_memory(start_position, size)

    output = computation.memory_read(start_position, size)
    computation.output = bytes(output)
    raise Revert(computation.output)


def selfdestruct(computation):
    beneficiary = force_bytes_to_address(computation.stack_pop1_bytes())
    _selfdestruct(computation, beneficiary)
    raise Halt('SELFDESTRUCT')


def selfdestruct_eip150(computation):
    beneficiary = force_bytes_to_address(computation.stack_pop1_bytes())
    if not computation.state.account_db.account_exists(beneficiary):
        computation.consume_gas(
            constants.GAS_SELFDESTRUCT_NEWACCOUNT,
            reason=mnemonics.SELFDESTRUCT,
        )
    _selfdestruct(computation, beneficiary)


def selfdestruct_eip161(computation):
    beneficiary = force_bytes_to_address(computation.stack_pop1_bytes())
    is_dead = (
        not computation.state.account_db.account_exists(beneficiary) or
        computation.state.account_db.account_is_empty(beneficiary)
    )
    if is_dead and computation.state.account_db.get_balance(computation.transaction_context.this_chain_address):
        computation.consume_gas(
            constants.GAS_SELFDESTRUCT_NEWACCOUNT,
            reason=mnemonics.SELFDESTRUCT,
        )
    _selfdestruct(computation, beneficiary)

def selfdestruct_photon(computation: 'PhotonComputation'):
    raise DepreciatedVMFunctionality("Selfdestruct has been removed.")
    # if computation.transaction_context.tx_code_address is not None:
    #     raise ForbiddenOperationForSurrogateCall("Cannot execute selfdestruct from a surrogate call")
    #
    # selfdestruct_eip161(computation)


def _selfdestruct(computation, beneficiary):
    local_balance = computation.state.account_db.get_balance(computation.transaction_context.this_chain_address)
    beneficiary_balance = computation.state.account_db.get_balance(beneficiary)

    # 1st: Transfer to beneficiary
    computation.state.account_db.set_balance(beneficiary, local_balance + beneficiary_balance)
    # 2nd: Zero the balance of the address being deleted (must come after
    # sending to beneficiary in case the contract named itself as the
    # beneficiary.
    computation.state.account_db.set_balance(computation.transaction_context.this_chain_address, 0)

    computation.logger.debug(
        "SELFDESTRUCT: %s (%s) -> %s",
        encode_hex(computation.transaction_context.this_chain_address),
        local_balance,
        encode_hex(beneficiary),
    )

    # 3rd: Register the account to be deleted
    computation.register_account_for_deletion(beneficiary)
    raise Halt('SELFDESTRUCT')


class CreateOpcodeStackData:

    def __init__(self,
                 value: int,
                 memory_start: int,
                 memory_length: int,
                 salt: int = None) -> None:

        self.value = value
        self.memory_start = memory_start
        self.memory_length = memory_length
        self.salt = salt


class Create(Opcode):

    def max_child_gas_modifier(self, gas: int) -> int:
        return max_child_gas_eip150(gas)

    def get_gas_cost(self, data: CreateOpcodeStackData) -> int:
        return constants.GAS_CREATE + constants.GAS_SHA3WORD * ceil32(data.memory_length) // 32

    def generate_contract_address(self,
                                  stack_data: CreateOpcodeStackData,
                                  call_data: bytes,
                                  computation: 'PhotonComputation') -> Address:

        creation_nonce = computation.execution_context.computation_call_nonce
        # This will be incremented automatically when we add the external call to the computation

        contract_address = generate_contract_address(
            computation.transaction_context.this_chain_address,
            creation_nonce,
        )

        return contract_address

    def get_stack_data(self, computation: 'PhotonComputation') -> CreateOpcodeStackData:
        value, memory_start, memory_length = computation.stack_pop_ints(3)

        return CreateOpcodeStackData(value, memory_start, memory_length)

    def __call__(self, computation: 'PhotonComputation') -> None:
        if computation.msg.is_static:
            raise WriteProtection("Cannot modify state while inside of a STATICCALL context")

        stack_data = self.get_stack_data(computation)

        gas_cost = self.get_gas_cost(stack_data)
        computation.consume_gas(gas_cost, reason=self.mnemonic)

        computation.extend_memory(stack_data.memory_start, stack_data.memory_length)

        sender_balance = computation.state.account_db.get_balance(
            computation.transaction_context.this_chain_address
        )

        insufficient_funds = sender_balance < stack_data.value
        stack_too_deep = computation.msg.depth + 1 > constants.STACK_DEPTH_LIMIT

        if insufficient_funds or stack_too_deep:
            computation.stack_push_int(0)
            return

        call_data = computation.memory_read_bytes(
            stack_data.memory_start, stack_data.memory_length
        )

        create_msg_gas = self.max_child_gas_modifier(
            computation.get_gas_remaining()
        )
        computation.consume_gas(create_msg_gas, reason=self.mnemonic)

        contract_address = self.generate_contract_address(stack_data, call_data, computation)

        is_collision = computation.state.account_db.account_has_code_or_nonce(contract_address)

        if is_collision:
            self.logger.debug(
                "Address collision while creating contract: %s",
                encode_hex(contract_address),
            )
            computation.stack_push_int(0)
            return

        child_msg = computation.prepare_child_message(
            gas=create_msg_gas,
            to=constants.CREATE_CONTRACT_ADDRESS,
            value=stack_data.value,
            data=call_data,
            code=b'',
            create_address=contract_address,
        )
        self.apply_external_call_create_message(computation, child_msg, stack_data)


    def apply_external_call_create_message(self, computation: 'PhotonComputation', child_msg: Message, stack_data: CreateOpcodeStackData) -> None:
        initial_gas_given = child_msg.gas
        child_computation = computation.__class__(
                            computation.state,
                            child_msg,
                            computation.transaction_context,
                        ).simulate_apply_create_message()

        gas_remaining = child_computation.get_gas_remaining()
        gas_used = initial_gas_given - gas_remaining
        gas_needed_for_external_call = gas_used + GAS_TX
        if initial_gas_given < gas_needed_for_external_call:
            self.logger.debug(
                "Insufficient Gas for {}: provided: {} | needed: {}".format(
                    self.mnemonic,
                    initial_gas_given,
                    gas_needed_for_external_call
                )
            )
            computation.stack_push_int(0)
            return


        if child_computation.is_error:
            computation.stack_push_int(0)
        else:
            computation.stack_push_bytes(child_msg.create_address)
            computation.apply_external_call_message(child_msg)

        computation.return_gas(initial_gas_given-gas_needed_for_external_call)



class Create2(Create):

    def get_stack_data(self, computation: 'PhotonComputation') -> CreateOpcodeStackData:
        value, memory_start, memory_length, salt = computation.stack_pop_ints(4)

        return CreateOpcodeStackData(value, memory_start, memory_length, salt)

    def get_gas_cost(self, data: CreateOpcodeStackData) -> int:
        return constants.GAS_CREATE + constants.GAS_SHA3WORD * ceil32(data.memory_length) // 32

    def generate_contract_address(self,
                                  stack_data: CreateOpcodeStackData,
                                  call_data: bytes,
                                  computation: 'PhotonComputation') -> Address:

        return generate_safe_contract_address(
            computation.transaction_context.this_chain_address,
            stack_data.salt,
            call_data
        )

    def apply_external_call_create_message(self, computation: 'PhotonComputation', child_msg: Message, stack_data: CreateOpcodeStackData) -> None:
        initial_gas_given = child_msg.gas
        child_computation = computation.__class__(
                            computation.state,
                            child_msg,
                            computation.transaction_context,
                        ).simulate_apply_create_message()

        gas_remaining = child_computation.get_gas_remaining()
        gas_used = initial_gas_given - gas_remaining
        gas_needed_for_external_call = gas_used + GAS_TX
        if initial_gas_given < gas_needed_for_external_call:
            self.logger.debug(
                "Insufficient Gas for {}: provided: {} | needed: {}".format(
                    self.mnemonic,
                    initial_gas_given,
                    gas_needed_for_external_call
                )
            )
            computation.stack_push_int(0)
            return

        child_msg.salt = stack_data.salt

        if child_computation.is_error:
            computation.stack_push_int(0)
        else:
            computation.stack_push_bytes(child_msg.create_address)
            computation.apply_external_call_message(child_msg)

        computation.return_gas(initial_gas_given-gas_needed_for_external_call)

