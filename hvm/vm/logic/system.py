from hvm import constants
from hvm.exceptions import (
    Halt,
    Revert,
    WriteProtection,
    ForbiddenOperationForSurrogateCall, DepreciatedVMFunctionality)

from hvm.utils.address import (
    force_bytes_to_address,
    generate_contract_address,
)
from hvm.utils.hexadecimal import (
    encode_hex,
)
from hvm.vm import mnemonics

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


class Create(Opcode):
    def max_child_gas_modifier(self, gas):
        return gas

    def __call__(self, computation):
        raise NotImplementedError('Create opcode needs to be implemented')

        computation.consume_gas(self.gas_cost, reason=self.mnemonic)

        value, start_position, size = computation.stack_pop_ints(
            num_items=3
        )

        computation.extend_memory(start_position, size)

        insufficient_funds = computation.state.account_db.get_balance(
            computation.transaction_context.this_chain_address
        ) < value
        stack_too_deep = computation.msg.depth + 1 > constants.STACK_DEPTH_LIMIT

        if insufficient_funds or stack_too_deep:
            computation.stack_push_int(0)
            return

        call_data = computation.memory_read(start_position, size)

        create_msg_gas = self.max_child_gas_modifier(
            computation.get_gas_remaining()
        )
        computation.consume_gas(create_msg_gas, reason="CREATE")

        creation_nonce = computation.state.account_db.get_nonce(computation.transaction_context.this_chain_address)
        computation.state.account_db.increment_nonce(computation.transaction_context.this_chain_address)

        contract_address = generate_contract_address(
            computation.transaction_context.this_chain_address,
            creation_nonce,
        )

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
            value=value,
            data=b'',
            code=call_data,
            create_address=contract_address,
        )

        child_computation = computation.apply_child_computation(child_msg)

        if child_computation.is_error:
            computation.stack_push_int(0)
        else:
            computation.stack_push_bytes(contract_address)
        computation.return_gas(child_computation.get_gas_remaining())


class CreateEIP150(Create):
    def max_child_gas_modifier(self, gas):
        return max_child_gas_eip150(gas)


class CreateByzantium(CreateEIP150):
    def __call__(self, computation):
        if computation.msg.is_static:
            raise WriteProtection("Cannot modify state while inside of a STATICCALL context")
        return super(CreateEIP150, self).__call__(computation)


# need to implement this
# class Create2(CreateByzantium):
#
#     def get_stack_data(self, computation: ComputationAPI) -> CreateOpcodeStackData:
#         endowment, memory_start, memory_length, salt = computation.stack_pop_ints(4)
#
#         return CreateOpcodeStackData(endowment, memory_start, memory_length, salt)
#
#     def get_gas_cost(self, data: CreateOpcodeStackData) -> int:
#         return constants.GAS_CREATE + constants.GAS_SHA3WORD * ceil32(data.memory_length) // 32
#
#     def generate_contract_address(self,
#                                   stack_data: CreateOpcodeStackData,
#                                   call_data: bytes,
#                                   computation: ComputationAPI) -> Address:
#
#         computation.state.increment_nonce(computation.msg.storage_address)
#         return generate_safe_contract_address(
#             computation.msg.storage_address,
#             stack_data.salt,
#             call_data
#         )
#
#     def apply_create_message(self, computation: ComputationAPI, child_msg: MessageAPI) -> None:
#         # We need to ensure that creation operates on empty storage **and**
#         # that if the initialization code fails that we revert the account back
#         # to its original state root.
#         snapshot = computation.state.snapshot()
#
#         computation.state.delete_storage(child_msg.storage_address)
#
#         child_computation = computation.apply_child_computation(child_msg)
#
#         if child_computation.is_error:
#             computation.state.revert(snapshot)
#             computation.stack_push_int(0)
#         else:
#             computation.state.commit(snapshot)
#             computation.stack_push_bytes(child_msg.storage_address)
#
#         computation.return_gas(child_computation.get_gas_remaining())