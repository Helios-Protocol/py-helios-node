from eth_utils import encode_hex

from hvm.exceptions import ValidationError
from hvm.rlp.transactions import (
    BaseTransaction,
    BaseReceiveTransaction 
)
from typing import Union, Optional # noqa: F401

from hvm.vm.forks.boson.validation import validate_boson_transaction, \
    validate_boson_transaction_against_header


def validate_photon_transaction(account_db,
                               send_transaction: BaseTransaction,
                               this_chain_address:bytes,
                               receive_transaction: Optional[BaseReceiveTransaction] = None,
                               refund_receive_transaction: Optional[BaseReceiveTransaction] = None):

    validate_boson_transaction(account_db,
                               send_transaction,
                               this_chain_address,
                               receive_transaction,
                               refund_receive_transaction)

    if receive_transaction is None and refund_receive_transaction is None:
        # This is a send transaction
        if account_db.is_smart_contract(this_chain_address) and send_transaction.caller != this_chain_address:
            # Send transactions on a smart contract must specify the caller as this chain address
            raise ValidationError('Send transaction {} on smart contract chain {} has not specified the correct caller. Caller: {}'.format(
                encode_hex(send_transaction.hash),
                encode_hex(this_chain_address),
                encode_hex(send_transaction.caller)
            ))


def validate_photon_transaction_against_header(_vm, base_header, send_transaction):
    return validate_boson_transaction_against_header(_vm, base_header, send_transaction)
