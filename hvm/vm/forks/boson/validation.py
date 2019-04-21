from hvm.rlp.transactions import (
    BaseTransaction,
    BaseReceiveTransaction 
)
from typing import Union, Optional # noqa: F401

from hvm.vm.forks.helios_testnet.validation import validate_helios_testnet_transaction, \
    validate_helios_testnet_transaction_against_header


def validate_boson_transaction(account_db,
                               send_transaction: BaseTransaction,
                               caller_chain_address:bytes,
                               receive_transaction: Optional[BaseReceiveTransaction] = None,
                               refund_receive_transaction: Optional[BaseReceiveTransaction] = None):

    return validate_helios_testnet_transaction(account_db,
                                               send_transaction,
                                               caller_chain_address,
                                               receive_transaction,
                                               refund_receive_transaction)


def validate_boson_transaction_against_header(_vm, base_header, send_transaction):
    return validate_helios_testnet_transaction_against_header(_vm, base_header, send_transaction)
