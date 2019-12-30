from abc import (
    ABCMeta,
    abstractmethod
)

from hvm import constants

from hvm.exceptions import (
    OutOfGas,
    AttemptedToAccessExternalStorage,
    ForbiddenOperationForSurrogateCall,
    DepreciatedVMFunctionality, RequiresCodeFromMissingChain, RequiresCodeFromChainInFuture)


from hvm.vm.opcode import (
    Opcode,
)

from hvm.utils.address import (
    force_bytes_to_address,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hvm.vm.forks.photon import PhotonComputation

def max_child_gas_eip150(gas):
    return gas - (gas // 64)

def compute_msg_gas_internal(computation, gas, extra_gas, value, mnemonic, callstipend):
    if computation.get_gas_remaining() < extra_gas:
        # It feels wrong to raise an OutOfGas exception outside of GasMeter,
        # but I don't see an easy way around it.
        raise OutOfGas("Out of gas: Needed {0} - Remaining {1} - Reason: {2}".format(
            extra_gas,
            computation.get_gas_remaining(),
            mnemonic,
        ))
    gas = min(
        gas,
        max_child_gas_eip150(computation.get_gas_remaining() - extra_gas))
    total_fee = gas + extra_gas
    child_msg_gas = gas + (callstipend if value else 0)
    return child_msg_gas, total_fee


class BaseCall(Opcode, metaclass=ABCMeta):
    @abstractmethod
    def compute_msg_gas(self, computation, gas, to, value):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def compute_msg_extra_gas(self, computation, gas, to, value):
        raise NotImplementedError("Must be implemented by subclasses")
    
    @abstractmethod
    def get_call_params(self, computation):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def __call__(self, computation):
        raise NotImplementedError("Must be implemented by subclasses")


class InternalCall(BaseCall):
    def compute_msg_gas(self, computation, gas, to, value):
        extra_gas = self.compute_msg_extra_gas(computation, gas, to, value)
        callstipend = 0
        return compute_msg_gas_internal(
            computation, gas, extra_gas, value, self.mnemonic, callstipend)

    def compute_msg_extra_gas(self, computation, gas, to, value):
        return 0

    def get_call_params(self, computation):
        pass

    def __call__(self, computation):
        computation.consume_gas(
            self.gas_cost,
            reason=self.mnemonic,
        )

        (
            gas,
            value,
            to,
            sender,
            code_address,
            memory_input_start_position,
            memory_input_size,
            memory_output_start_position,
            memory_output_size,
            should_transfer_value,
            is_static,
            use_external_smart_contract_storage,
        ) = self.get_call_params(computation)

        computation.extend_memory(memory_input_start_position, memory_input_size)
        computation.extend_memory(memory_output_start_position, memory_output_size)

        call_data = computation.memory_read_bytes(memory_input_start_position, memory_input_size)

        #
        # Message gas allocation and fees
        #
        child_msg_gas, child_msg_gas_fee = self.compute_msg_gas(computation, gas, to, value)
        computation.consume_gas(child_msg_gas_fee, reason=self.mnemonic)

        # Pre-call checks
        sender_balance = computation.state.account_db.get_balance(
            computation.transaction_context.this_chain_address
        )

        insufficient_funds = should_transfer_value and sender_balance < value
        stack_too_deep = computation.msg.depth + 1 > constants.STACK_DEPTH_LIMIT

        if use_external_smart_contract_storage and not is_static:
            raise AttemptedToAccessExternalStorage("Computations using external smart contract storage must be static.")

        if insufficient_funds or stack_too_deep:
            computation.return_data = b''
            if insufficient_funds:
                err_message = "Insufficient Funds: have: {0} | need: {1}".format(
                    sender_balance,
                    value,
                )
            elif stack_too_deep:
                err_message = "Stack Limit Reached"
            else:
                raise Exception("Invariant: Unreachable code path")

            self.logger.debug(
                "%s failure: %s",
                self.mnemonic,
                err_message,
            )
            computation.return_gas(child_msg_gas)
            computation.stack_push_int(0)
        else:
            current_code_address = code_address if code_address else to

            if not computation.state.account_db.account_has_chain(current_code_address):
                raise RequiresCodeFromMissingChain(code_address = current_code_address)
            if computation.execution_context.timestamp <= computation.state.account_db.get_contract_deploy_timestamp(current_code_address):
                raise RequiresCodeFromChainInFuture("This computation requires code from a chain that was deployed in the future")
            code = computation.state.account_db.get_code(current_code_address)

            
            child_msg_kwargs = {
                'gas': child_msg_gas,
                'value': value,
                'to': to,
                'data': call_data,
                'code': code,
                'code_address': code_address,
                'should_transfer_value': should_transfer_value,
                'is_static': is_static,
                'nonce': computation.msg.nonce,
                'use_external_smart_contract_storage': use_external_smart_contract_storage,
            }
            if sender is not None:
                child_msg_kwargs['sender'] = sender

            child_msg = computation.prepare_child_message(**child_msg_kwargs)

            child_computation = computation.apply_child_computation(child_msg)

            if child_computation.is_error:
                computation.stack_push_int(0)
            else:
                computation.stack_push_int(1)

            if not child_computation.should_erase_return_data:
                actual_output_size = min(memory_output_size, len(child_computation.output))
                computation.memory_write(
                    memory_output_start_position,
                    actual_output_size,
                    child_computation.output[:actual_output_size],
                )

            if child_computation.should_return_gas:
                computation.return_gas(child_computation.get_gas_remaining())


class BaseExternalCall(BaseCall):
    def compute_msg_gas(self, computation, gas, to, value, data):
        from hvm.vm.forks.photon.transactions import get_photon_intrinsic_gas_normal
        extra_gas = self.compute_msg_extra_gas(computation, gas, to, value)
        tx_intrinsic_gas = get_photon_intrinsic_gas_normal(data)
        
        child_msg_gas, total_fee = compute_msg_gas_internal(
            computation, gas, extra_gas, value, self.mnemonic,
            constants.GAS_CALLSTIPEND)
        
        child_msg_gas = child_msg_gas + tx_intrinsic_gas
        total_fee = total_fee + tx_intrinsic_gas
        
        return child_msg_gas, total_fee

    def compute_msg_extra_gas(self, computation, gas, to, value):
        account_is_dead = (
            not computation.state.account_db.account_exists(to) or
            computation.state.account_db.account_is_empty(to)
        )

        transfer_gas_fee = constants.GAS_CALLVALUE if value else 0
        create_gas_fee = constants.GAS_NEWACCOUNT if (account_is_dead and value) else 0
        return transfer_gas_fee + create_gas_fee
    
    def get_call_params(self, computation):
        gas = computation.stack_pop1_int()
        to = force_bytes_to_address(computation.stack_pop1_bytes())

        (
            value,
            memory_input_start_position,
            memory_input_size,
            memory_output_start_position,
            memory_output_size,
        ) = computation.stack_pop_ints(num_items=5)

        return (
            gas,
            value,
            to,
            None,  # sender
            None,  # code_address
            memory_input_start_position,
            memory_input_size,
            memory_output_start_position,
            memory_output_size,
            True,  # should_transfer_value,
            computation.msg.is_static,
            False
        )

    def __call__(self, computation: 'PhotonComputation'):
        computation.consume_gas(
            self.gas_cost,
            reason=self.mnemonic,
        )

        (
            gas,
            value,
            to,
            sender,
            code_address,
            memory_input_start_position,
            memory_input_size,
            memory_output_start_position,
            memory_output_size,
            should_transfer_value,
            is_static,
            execute_on_send,
        ) = self.get_call_params(computation)


        computation.extend_memory(memory_input_start_position, memory_input_size)

        if memory_output_start_position is not None:
            computation.extend_memory(memory_output_start_position, memory_output_size)

        call_data = computation.memory_read_bytes(memory_input_start_position, memory_input_size)

        if is_static:
            raise AttemptedToAccessExternalStorage("Static calls cannot use call or surrogatecall because they modify the state")

        # Pre-call checks
        # This could actually execute on send if it is within a create transaction. But not if that create transaction has tx_execute_on_send
        # We allow this now.
        # if not computation.transaction_context.is_receive and computation.transaction_context.tx_execute_on_send:
        #     raise ForbiddenOperationForExecutingOnSend("Computation executing on send cannot create new call transactions.")

        if computation.transaction_context.is_surrogate_call:
            raise ForbiddenOperationForSurrogateCall("Surrogatecalls are not allowed to create children calls or surrogatecalls. They are only allowed to create delegatecalls.")

        #
        # Message gas allocation and fees
        #
        child_msg_gas, child_msg_gas_fee = self.compute_msg_gas(computation, gas, to, value, call_data)

        computation.consume_gas(child_msg_gas_fee, reason=self.mnemonic)

        sender_balance = computation.state.account_db.get_balance(
            computation.transaction_context.this_chain_address
        )

        insufficient_funds = should_transfer_value and sender_balance < value

        stack_too_deep = computation.msg.depth + 1 > constants.STACK_DEPTH_LIMIT

        if insufficient_funds or stack_too_deep:
            computation.return_data = b''
            if insufficient_funds:
                err_message = "Insufficient Funds: have: {0} | need: {1}".format(
                    sender_balance,
                    value,
                )
            elif stack_too_deep:
                err_message = "Stack Limit Reached"
            else:
                raise Exception("Invariant: Unreachable code path")

            self.logger.debug(
                "%s failure: %s",
                self.mnemonic,
                err_message,
            )
            computation.return_gas(child_msg_gas)
            computation.stack_push_int(0)
        else:


            child_msg_kwargs = {
                'gas': child_msg_gas,
                'value': value,
                'to': to,
                'data': call_data,
                'code': b'',
                'code_address': code_address,
                'should_transfer_value': should_transfer_value,
                'is_static': False,
                'execute_on_send': execute_on_send,
            }
            if sender is not None:
                child_msg_kwargs['sender'] = sender

            child_msg = computation.prepare_child_message(**child_msg_kwargs)

            #
            # Now we send it back to the vm to make a send transaction out of it.
            #
            computation.apply_external_call_message(child_msg)

            # push 1 to show there was no error
            computation.stack_push_int(1)


class CallCode(InternalCall):
    def get_call_params(self, computation):
        gas = computation.stack_pop1_int()
        code_address = force_bytes_to_address(computation.stack_pop1_bytes())

        (
            value,
            memory_input_start_position,
            memory_input_size,
            memory_output_start_position,
            memory_output_size,
        ) = computation.stack_pop_ints(num_items=5)

        to = computation.transaction_context.this_chain_address
        sender = computation.transaction_context.this_chain_address

        if value != 0:
            raise DepreciatedVMFunctionality("CallCode cannot send value to another chain. Value must = 0")

        return (
            gas,
            value,
            to,
            sender,
            code_address,
            memory_input_start_position,
            memory_input_size,
            memory_output_start_position,
            memory_output_size,
            False,  # should_transfer_value,
            computation.msg.is_static,
            computation.msg.use_external_smart_contract_storage,
        )


class DelegateCall(InternalCall):
    def get_call_params(self, computation):
        gas = computation.stack_pop1_int()
        code_address = force_bytes_to_address(computation.stack_pop1_bytes())

        (
            memory_input_start_position,
            memory_input_size,
            memory_output_start_position,
            memory_output_size,
        ) = computation.stack_pop_ints(num_items=4)

        to = computation.transaction_context.this_chain_address
        sender = computation.msg.sender
        value = computation.msg.value

        return (
            gas,
            value,
            to,
            sender,
            code_address,
            memory_input_start_position,
            memory_input_size,
            memory_output_start_position,
            memory_output_size,
            False,  # should_transfer_value,
            computation.msg.is_static,
            computation.msg.use_external_smart_contract_storage,
        )

# StaticCall will allow the smart contract read only access to the external smart contract storage
class StaticCall(InternalCall):
    def get_call_params(self, computation):
        gas = computation.stack_pop1_int()
        to = force_bytes_to_address(computation.stack_pop1_bytes())

        (
            memory_input_start_position,
            memory_input_size,
            memory_output_start_position,
            memory_output_size,
        ) = computation.stack_pop_ints(num_items=4)

        return (
            gas,
            0,  # value
            to,
            None,  # sender
            None,  # code_address
            memory_input_start_position,
            memory_input_size,
            memory_output_start_position,
            memory_output_size,
            False,  # should_transfer_value,
            True,  # is_static,
            True, # use_external_smart_contract_storage
        )


#
# Helios
#
class StaticCallHelios(StaticCall):
    def __call__(self, computation):
        raise AttemptedToAccessExternalStorage(
            "The StaticCall function uses storage on a different contract. This is not allowed on Helios. Use DelegateCall instead.")

class CallHelios(BaseExternalCall):
    pass

#
# Photon
#
class SurrogateCall(CallHelios):
    def get_call_params(self, computation):
        gas = computation.stack_pop1_int()
        code_address = force_bytes_to_address(computation.stack_pop1_bytes())
        value = computation.stack_pop1_int()
        execute_on_send = bool(computation.stack_pop1_int())
        to = force_bytes_to_address(computation.stack_pop1_bytes())

        (
            memory_input_start_position,
            memory_input_size
        ) = computation.stack_pop_ints(num_items=2)

        return (
            gas,
            value,
            to,
            None,  # sender
            code_address,  # code_address
            memory_input_start_position,
            memory_input_size,
            None,
            None,
            True,  # should_transfer_value,
            computation.msg.is_static,
            execute_on_send
        )

class StaticCallPhoton(StaticCall):
    pass