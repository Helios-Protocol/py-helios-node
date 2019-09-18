from hvm import constants

from hvm.utils.hexadecimal import (
    encode_hex,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hvm.vm.forks.photon import PhotonComputation


def sstore(computation):
    slot, value = computation.stack_pop(num_items=2, type_hint=constants.UINT256)

    current_value = computation.state.account_db.get_storage(
        address=computation.transaction_context.this_chain_address,
        slot=slot,
    )

    is_currently_empty = not bool(current_value)
    is_going_to_be_empty = not bool(value)

    if is_currently_empty:
        gas_refund = 0
    elif is_going_to_be_empty:
        gas_refund = constants.REFUND_SCLEAR
    else:
        gas_refund = 0

    if is_currently_empty and is_going_to_be_empty:
        gas_cost = constants.GAS_SRESET
    elif is_currently_empty:
        gas_cost = constants.GAS_SSET
    elif is_going_to_be_empty:
        gas_cost = constants.GAS_SRESET
    else:
        gas_cost = constants.GAS_SRESET

    computation.consume_gas(gas_cost, reason="SSTORE: {0}[{1}] -> {2} ({3})".format(
        encode_hex(computation.transaction_context.this_chain_address),
        slot,
        value,
        current_value,
    ))

    if gas_refund:
        computation.refund_gas(gas_refund)

    computation.state.account_db.set_storage(
        address=computation.transaction_context.this_chain_address,
        slot=slot,
        value=value,
    )


def sload(computation):
    slot = computation.stack_pop(type_hint=constants.UINT256)

    value = computation.state.account_db.get_storage(
        address=computation.transaction_context.this_chain_address,
        slot=slot,
    )
    computation.stack_push(value)


def sstore_photon(computation: 'PhotonComputation'):
    slot, value = computation.stack_pop(num_items=2, type_hint=constants.UINT256)

    if computation.transaction_context.tx_code_address is None:
        current_value = computation.state.account_db.get_storage(
            address=computation.transaction_context.this_chain_address,
            slot=slot,
        )
    else:
        current_value = computation.state.account_db.get_external_smart_contract_storage(
            address=computation.transaction_context.this_chain_address,
            smart_contract_address=computation.transaction_context.tx_code_address,
            slot=slot,
        )


    is_currently_empty = not bool(current_value)
    is_going_to_be_empty = not bool(value)

    if is_currently_empty:
        gas_refund = 0
    elif is_going_to_be_empty:
        gas_refund = constants.REFUND_SCLEAR
    else:
        gas_refund = 0

    if is_currently_empty and is_going_to_be_empty:
        gas_cost = constants.GAS_SRESET
    elif is_currently_empty:
        gas_cost = constants.GAS_SSET
    elif is_going_to_be_empty:
        gas_cost = constants.GAS_SRESET
    else:
        gas_cost = constants.GAS_SRESET

    computation.consume_gas(gas_cost, reason="SSTORE: {0}[{1}] -> {2} ({3})".format(
        encode_hex(computation.transaction_context.this_chain_address),
        slot,
        value,
        current_value,
    ))

    if gas_refund:
        computation.refund_gas(gas_refund)

    if computation.transaction_context.tx_code_address is None:
        computation.state.account_db.set_storage(
            address=computation.transaction_context.this_chain_address,
            slot=slot,
            value=value,
        )
    else:
        computation.state.account_db.set_external_smart_contract_storage(
            address=computation.transaction_context.this_chain_address,
            smart_contract_address=computation.transaction_context.tx_code_address,
            slot=slot,
            value=value,
        )


def sload_photon(computation: 'PhotonComputation'):
    slot = computation.stack_pop(type_hint=constants.UINT256)

    if computation.transaction_context.tx_code_address is None:
        value = computation.state.account_db.get_storage(
            address=computation.transaction_context.this_chain_address,
            slot=slot,
        )
    else:
        value = computation.state.account_db.get_external_smart_contract_storage(
            address=computation.transaction_context.this_chain_address,
            smart_contract_address=computation.transaction_context.tx_code_address,
            slot=slot,
        )
    computation.stack_push(value)
