
from .constants import (
    EIP658_TRANSACTION_STATUS_CODE_FAILURE,
    EIP658_TRANSACTION_STATUS_CODE_SUCCESS,
)

from .validation import validate_helios_testnet_transaction_against_header

from .blocks import (
    HeliosTestnetBlock,
    HeliosTestnetQueueBlock,
)
from .consensus import HeliosTestnetBlockConflictMessage

from hvm.rlp.transactions import (
        BaseTransaction,
        BaseReceiveTransaction,
)

from .headers import (
    create_helios_testnet_header_from_parent,
    configure_helios_testnet_header,
)
from .state import HeliosTestnetState
from hvm.vm.base import VM

from hvm.rlp.logs import (
    Log,
)

from hvm.rlp.receipts import (
    Receipt,
)


def make_helios_testnet_receipt(base_header, transaction, computation):
    logs = [
        Log(address, topics, data)
        for address, topics, data
        in computation.get_log_entries()
    ]

    gas_remaining = computation.get_gas_remaining()
    gas_refund = computation.get_gas_refund()
    if isinstance(transaction, BaseTransaction):
        tx_gas_used = (
            transaction.gas - gas_remaining
        ) - min(
            gas_refund,
            (transaction.gas - gas_remaining) // 2,
        )
    else:
        tx_gas_used = (
            transaction.transaction.gas - gas_remaining
        ) - min(
            gas_refund,
            (transaction.transaction.gas - gas_remaining) // 2,
        )
    #receive transactions dont use gas.
    if isinstance(transaction, BaseTransaction):
        gas_used = base_header.gas_used + tx_gas_used
    else:
        gas_used = base_header.gas_used
    
    if computation.is_error:
        status_code = EIP658_TRANSACTION_STATUS_CODE_FAILURE
    else:
        status_code = EIP658_TRANSACTION_STATUS_CODE_SUCCESS
        
    receipt = Receipt(
        status_code=status_code,
        gas_used=gas_used,
        logs=logs,
    )
    
    return receipt


class HeliosTestnetVM(VM):
    # fork name
    fork = 'helios_testnet'

    # classes
    block_class = HeliosTestnetBlock  # type: Type[BaseBlock]
    queue_block_class = HeliosTestnetQueueBlock  # type: Type[BaseBlock]
    block_conflict_message_class = HeliosTestnetBlockConflictMessage
    _state_class = HeliosTestnetState  # type: Type[BaseState]

    # Methods
    create_header_from_parent = staticmethod(create_helios_testnet_header_from_parent)
    configure_header = configure_helios_testnet_header
    make_receipt = staticmethod(make_helios_testnet_receipt)
    validate_transaction_against_header = validate_helios_testnet_transaction_against_header
