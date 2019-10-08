from hvm import constants

from hvm.utils.hexadecimal import (
    encode_hex,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hvm.vm.forks.photon import PhotonComputation


def sstore(computation):
    slot, value = computation.stack_pop_ints(num_items=2)

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
    slot = computation.stack_pop1_int()

    value = computation.state.account_db.get_storage(
        address=computation.transaction_context.this_chain_address,
        slot=slot,
    )
    computation.stack_push_int(value)


def sstore_photon(computation: 'PhotonComputation'):
    slot, value = computation.stack_pop_ints(num_items=2)

    if computation.transaction_context.is_surrogate_call or computation.transaction_context.is_send:
        if computation.msg.is_create:
            # Save it in the storage allocated for the newly created address
            current_value = computation.state.account_db.get_external_smart_contract_storage(
                address=computation.transaction_context.this_chain_address,
                smart_contract_address=computation.msg.resolved_to,
                slot=slot,
            )
        else:
            # Save it in the storage allocated for the original contract address
            current_value = computation.state.account_db.get_external_smart_contract_storage(
                address=computation.transaction_context.this_chain_address,
                smart_contract_address=computation.transaction_context.smart_contract_storage_address,
                slot=slot,
            )

    else:
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


    if computation.transaction_context.is_surrogate_call or computation.transaction_context.is_send:
        if computation.msg.is_create:
            # Save it in the storage allocated for the newly created address
            computation.state.account_db.set_external_smart_contract_storage(
                address=computation.transaction_context.this_chain_address,
                smart_contract_address=computation.msg.resolved_to,
                slot=slot,
                value=value,
            )
        else:
            # Save it in the storage allocated for the original contract address
            computation.state.account_db.set_external_smart_contract_storage(
                address=computation.transaction_context.this_chain_address,
                smart_contract_address=computation.transaction_context.smart_contract_storage_address,
                slot=slot,
                value=value,
            )

    else:
        computation.state.account_db.set_storage(
            address=computation.transaction_context.this_chain_address,
            slot=slot,
            value=value,
        )



def sload_photon(computation: 'PhotonComputation'):
    slot = computation.stack_pop1_int()

    if computation.transaction_context.is_surrogate_call or computation.transaction_context.is_send:
        if computation.msg.is_create:
            # Save it in the storage allocated for the newly created address
            value = computation.state.account_db.get_external_smart_contract_storage(
                address=computation.transaction_context.this_chain_address,
                smart_contract_address=computation.msg.resolved_to,
                slot=slot,
            )
        else:
            # Save it in the storage allocated for the original contract address
            value = computation.state.account_db.get_external_smart_contract_storage(
                address=computation.transaction_context.this_chain_address,
                smart_contract_address=computation.transaction_context.smart_contract_storage_address,
                slot=slot,
            )

    else:
        value = computation.state.account_db.get_storage(
            address=computation.transaction_context.this_chain_address,
            slot=slot,
        )


    computation.stack_push_int(value)
