from hvm import constants
from hvm.exceptions import OutOfGas

from hvm.utils.hexadecimal import (
    encode_hex,
)
from typing import TYPE_CHECKING, NamedTuple
from functools import partial
if TYPE_CHECKING:
    from hvm.vm.forks.photon import PhotonComputation


def get_value_from_storage(computation, slot, from_journal = True):
    if computation.msg.use_external_smart_contract_storage:
        # In this case, we want to use the external smart contract storage of the smart contract that provided the currently executing code
        current_value = computation.state.account_db.get_external_smart_contract_storage(
            address=computation.transaction_context.this_chain_address,
            smart_contract_address=computation.msg.code_address,
            slot=slot,
            from_journal=from_journal
        )
    elif computation.transaction_context.is_surrogate_call or computation.transaction_context.is_send:
        if computation.msg.is_create:
            # Load it from the storage allocated for the newly created address
            current_value = computation.state.account_db.get_external_smart_contract_storage(
                address=computation.transaction_context.this_chain_address,
                smart_contract_address=computation.msg.resolved_to,
                slot=slot,
                from_journal=from_journal
            )
        else:

            # Load it from the storage allocated for the original contract address
            current_value = computation.state.account_db.get_external_smart_contract_storage(
                address=computation.transaction_context.this_chain_address,
                smart_contract_address=computation.transaction_context.smart_contract_storage_address,
                slot=slot,
                from_journal=from_journal
            )
            # print("LOADING VALUE {} \n"
            #       "address {} \n"
            #       "smart_contract_address {} \n"
            #       "slot {} \n"
            #       "from_journal {} ".format(current_value,
            #                                 encode_hex(computation.transaction_context.this_chain_address),
            #                                 encode_hex(computation.transaction_context.smart_contract_storage_address),
            #                                 slot,
            #                                 from_journal))

    else:
        current_value = computation.state.account_db.get_storage(
            address=computation.transaction_context.this_chain_address,
            slot=slot,
            from_journal=from_journal
        )
    return current_value

def set_value_to_storage(computation, slot, value):
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

            # print("SETTING VALUE {} \n"
            #       "address {} \n"
            #       "smart_contract_address {} \n"
            #       "slot {} ".format(value,
            #                                 encode_hex(computation.transaction_context.this_chain_address),
            #                                 encode_hex(computation.transaction_context.smart_contract_storage_address),
            #                                 slot))

    else:
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


# def sstore(computation: 'PhotonComputation'):
#     slot, value = computation.stack_pop_ints(num_items=2)
#
#     current_value = get_value_from_storage(computation, slot)
#
#     is_currently_empty = not bool(current_value)
#     is_going_to_be_empty = not bool(value)
#
#     if is_currently_empty:
#         gas_refund = 0
#     elif is_going_to_be_empty:
#         gas_refund = constants.REFUND_SCLEAR
#     else:
#         gas_refund = 0
#
#     if is_currently_empty and is_going_to_be_empty:
#         gas_cost = constants.GAS_SRESET
#     elif is_currently_empty:
#         gas_cost = constants.GAS_SSET
#     elif is_going_to_be_empty:
#         gas_cost = constants.GAS_SRESET
#     else:
#         gas_cost = constants.GAS_SRESET
#
#     computation.consume_gas(gas_cost, reason="SSTORE: {0}[{1}] -> {2} ({3})".format(
#         encode_hex(computation.transaction_context.this_chain_address),
#         slot,
#         value,
#         current_value,
#     ))
#
#     if gas_refund:
#         computation.refund_gas(gas_refund)
#
#
#     set_value_to_storage(computation, slot, value)


class NetSStoreGasSchedule(NamedTuple):
    base: int  # the gas cost when nothing changes (eg~ dirty->dirty, clean->clean, etc)
    create: int  # a brand new value, where none previously existed, aka init or set
    update: int  # a change to a value when the value was previously unchanged, aka clean, reset
    remove_refund: int  # the refund for removing a value, aka: clear_refund




def net_sstore(gas_schedule: NetSStoreGasSchedule, computation: 'PhotonComputation') -> None:
    gas_remaining = computation.get_gas_remaining()
    if gas_remaining <= 2300:
        raise OutOfGas(
            "Net-metered SSTORE always fails below 2300 gas, per EIP-2200",
            gas_remaining,
        )

    slot, value = computation.stack_pop_ints(2)

    current_value = get_value_from_storage(computation, slot)

    original_value = get_value_from_storage(computation, slot, False)

    gas_refund = 0

    if current_value == value:
        gas_cost = gas_schedule.base
    else:
        if original_value == current_value:
            if original_value == 0:
                gas_cost = gas_schedule.create
            else:
                gas_cost = gas_schedule.update

                if value == 0:
                    gas_refund += gas_schedule.remove_refund
        else:
            gas_cost = gas_schedule.base

            if original_value != 0:
                if current_value == 0:
                    gas_refund -= gas_schedule.remove_refund
                if value == 0:
                    gas_refund += gas_schedule.remove_refund

            if original_value == value:
                if original_value == 0:
                    gas_refund += (gas_schedule.create - gas_schedule.base)
                else:
                    gas_refund += (gas_schedule.update - gas_schedule.base)

    computation.consume_gas(
        gas_cost,
        reason="SSTORE: {0}[{1}] -> {2} (current: {3} / original: {4})".format(
            encode_hex(computation.transaction_context.this_chain_address),
            slot,
            value,
            current_value,
            original_value,
        )
    )

    if gas_refund:
        computation.refund_gas(gas_refund)

    set_value_to_storage(computation, slot, value)


GAS_SCHEDULE_PHOTON_NET_SSTORE = NetSStoreGasSchedule(
    base=800,
    create=20000,
    update=5000,
    remove_refund=15000,
)

sstore_photon = partial(net_sstore, GAS_SCHEDULE_PHOTON_NET_SSTORE)


def sload_photon(computation: 'PhotonComputation'):
    slot = computation.stack_pop1_int()

    value = get_value_from_storage(computation, slot)

    computation.stack_push_int(value)
