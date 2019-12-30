from eth_typing import Address
from eth_utils import encode_hex

from hvm import constants
from hvm.exceptions import (
    OutOfBoundsRead,
    DepreciatedVMFunctionality, AttemptedToAccessExternalStorage, RequiresCodeFromMissingChain,
    RequiresCodeFromChainInFuture)

from hvm.utils.address import (
    force_bytes_to_address,
)
from hvm.utils.numeric import (
    ceil32,
)
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from hvm.vm.computation import BaseComputation


def balance(computation):
    addr = force_bytes_to_address(computation.stack_pop1_bytes())
    if addr != computation.transaction_context.this_chain_address:
        raise AttemptedToAccessExternalStorage("Attempted to read the balance of another chain. This is not allowed.")
    _push_balance_of_address(addr, computation)

def selfbalance(computation: 'BaseComputation') -> None:
    _push_balance_of_address(computation.transaction_context.this_chain_address, computation)

def _push_balance_of_address(address: Address, computation: 'BaseComputation') -> None:
    balance = computation.state.account_db.get_balance(address)
    computation.stack_push_int(balance)

def origin(computation):
    computation.stack_push_bytes(computation.transaction_context.origin)

def execute_on_send(computation):
    val_int = 1 if computation.transaction_context.tx_execute_on_send else 0
    computation.stack_push_int(val_int)

def address(computation):
    computation.stack_push_bytes(computation.transaction_context.this_chain_address)

def code_address(computation):
    computation.stack_push_bytes(computation.transaction_context.smart_contract_storage_address)

def caller(computation):
    computation.stack_push_bytes(computation.msg.sender)


def callvalue(computation):
    computation.stack_push_int(computation.msg.value)


def calldataload(computation):
    """
    Load call data into memory.
    """
    start_position = computation.stack_pop1_int()

    value = computation.msg.data[start_position:start_position + 32]
    padded_value = value.ljust(32, b'\x00')
    normalized_value = padded_value.lstrip(b'\x00')

    computation.stack_push_bytes(normalized_value)


def calldatasize(computation):
    size = len(computation.msg.data)
    computation.stack_push_int(size)


def calldatacopy(computation):
    (
        mem_start_position,
        calldata_start_position,
        size,
    ) = computation.stack_pop_ints(num_items=3)

    computation.extend_memory(mem_start_position, size)

    word_count = ceil32(size) // 32
    copy_gas_cost = word_count * constants.GAS_COPY

    computation.consume_gas(copy_gas_cost, reason="CALLDATACOPY fee")

    value = computation.msg.data[calldata_start_position: calldata_start_position + size]
    padded_value = value.ljust(size, b'\x00')

    computation.memory_write(mem_start_position, size, padded_value)

def chain_id(computation: 'BaseComputation') -> None:
    computation.stack_push_int(computation.state.execution_context.network_id)

def codesize(computation):
    size = len(computation.code)
    computation.stack_push_int(size)


def codecopy(computation):
    (
        mem_start_position,
        code_start_position,
        size,
    ) = computation.stack_pop_ints(num_items=3)

    computation.extend_memory(mem_start_position, size)

    word_count = ceil32(size) // 32
    copy_gas_cost = constants.GAS_COPY * word_count

    computation.consume_gas(
        copy_gas_cost,
        reason="CODECOPY: word gas cost",
    )

    with computation.code.seek(code_start_position):
        code_bytes = computation.code.read(size)

    padded_code_bytes = code_bytes.ljust(size, b'\x00')

    computation.memory_write(mem_start_position, size, padded_code_bytes)


def gasprice(computation):
    computation.stack_push_int(computation.transaction_context.gas_price)


def extcodesize(computation):
    account = force_bytes_to_address(computation.stack_pop1_bytes())
    if not computation.state.account_db.account_has_chain(account):
        raise RequiresCodeFromMissingChain(code_address = account)
    if computation.execution_context.timestamp <= computation.state.account_db.get_contract_deploy_timestamp(account):
        raise RequiresCodeFromChainInFuture("This computation requires code from a chain that was deployed in the future")

    code_size = len(computation.state.account_db.get_code(account))

    computation.stack_push_int(code_size)


def extcodecopy(computation):
    account = force_bytes_to_address(computation.stack_pop1_bytes())
    (
        mem_start_position,
        code_start_position,
        size,
    ) = computation.stack_pop_ints(num_items=3)

    computation.extend_memory(mem_start_position, size)

    word_count = ceil32(size) // 32
    copy_gas_cost = constants.GAS_COPY * word_count

    computation.consume_gas(
        copy_gas_cost,
        reason='EXTCODECOPY: word gas cost',
    )

    if not computation.state.account_db.account_has_chain(account):
        raise RequiresCodeFromMissingChain(code_address = account)
    if computation.execution_context.timestamp <= computation.state.account_db.get_contract_deploy_timestamp(account):
        raise RequiresCodeFromChainInFuture("This computation requires code from a chain that was deployed in the future")

    code = computation.state.account_db.get_code(account)

    code_bytes = code[code_start_position:code_start_position + size]
    padded_code_bytes = code_bytes.ljust(size, b'\x00')

    computation.memory_write(mem_start_position, size, padded_code_bytes)


def extcodehash(computation: 'BaseComputation') -> None:
    """
    Return the code hash for a given address.
    EIP: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1052.md
    """
    account = force_bytes_to_address(computation.stack_pop1_bytes())
    state = computation.state

    if not computation.state.account_db.account_has_chain(account):
        raise RequiresCodeFromMissingChain(code_address = account)
    if computation.execution_context.timestamp <= computation.state.account_db.get_contract_deploy_timestamp(account):
        raise RequiresCodeFromChainInFuture("This computation requires code from a chain that was deployed in the future")

    if state.account_db.account_is_empty(account):
        computation.stack_push_bytes(constants.NULL_BYTE)
    else:
        computation.stack_push_bytes(state.account_db.get_code_hash(account))

def returndatasize(computation):
    size = len(computation.return_data)
    computation.stack_push_int(size)


def returndatacopy(computation):
    (
        mem_start_position,
        returndata_start_position,
        size,
    ) = computation.stack_pop_ints(num_items=3)

    if returndata_start_position + size > len(computation.return_data):
        raise OutOfBoundsRead(
            "Return data length is not sufficient to satisfy request.  Asked "
            "for data from index {0} to {1}.  Return data is {2} bytes in "
            "length.".format(
                returndata_start_position,
                returndata_start_position + size,
                len(computation.return_data),
            )
        )

    computation.extend_memory(mem_start_position, size)

    word_count = ceil32(size) // 32
    copy_gas_cost = word_count * constants.GAS_COPY

    computation.consume_gas(copy_gas_cost, reason="RETURNDATACOPY fee")

    value = computation.return_data[returndata_start_position: returndata_start_position + size]

    computation.memory_write(mem_start_position, size, value)
