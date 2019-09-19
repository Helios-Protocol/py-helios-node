from eth_typing import Address

from hvm.exceptions import (
    ValidationError,
)
from hvm.constants import (
    SECPK1_N,
    CREATE_CONTRACT_ADDRESS
)
from typing import Union, Optional, TYPE_CHECKING # noqa: F401

if TYPE_CHECKING:
    from hvm.vm.forks.helios_testnet import HeliosTestnetTransaction, HeliosTestnetReceiveTransaction

'''
This only performs checks that can be done against the state.
'''
   
def validate_helios_testnet_transaction(account_db,
                                        send_transaction: 'HeliosTestnetTransaction',
                                        this_chain_address: Address,
                                        receive_transaction: Optional['HeliosTestnetReceiveTransaction'] = None,
                                        refund_receive_transaction: Optional['HeliosTestnetReceiveTransaction'] = None):

    #first find out if it is a send send_transaction or a receive transaction or a refund transaction
    if refund_receive_transaction is not None:
        #this is a refund transaction
        if refund_receive_transaction.is_refund is False:
            raise ValidationError(
                'Only refund transactions can be used for a refund. On this transaction is_from_refund = False.')

        if refund_receive_transaction.remaining_refund != 0:
            raise ValidationError(
                'Refund transactions must have 0 remaining refund')

        if send_transaction.sender != this_chain_address:
            raise ValidationError(
                'Refunds can only go back to the original chain that sent the initial transaction')

    elif receive_transaction is not None:
        #this is a receive transaction

        if send_transaction.to != this_chain_address and send_transaction.to != CREATE_CONTRACT_ADDRESS:
            raise ValidationError(
                'Receive transaction is trying to receive a transaction that is not meant for this chain')

        if receive_transaction.is_refund is True:
            raise ValidationError(
                'The receive transaction is incorrectly marked as a refund.')

    else:
        #this is a send transaction
        if send_transaction.s > SECPK1_N // 2 or send_transaction.s == 0:
            raise ValidationError("Invalid signature S value")

        if send_transaction.sender != this_chain_address and not account_db.is_smart_contract(this_chain_address):
            raise ValidationError(
                'Send transaction sender doesnt match the this_chain_address. If sending a tx, it must be sent by the sender chain address. Transaction sender = {}, this_chain_address = {}'
                    .format(send_transaction.sender, this_chain_address))

        gas_cost = send_transaction.gas * send_transaction.gas_price
        sender_balance = account_db.get_balance(send_transaction.sender)
    
        if sender_balance < gas_cost:
            raise ValidationError(
                "Sender account balance cannot afford txn gas. Balance:{}, gas cost: {}".format(sender_balance, gas_cost)
            )
    
        total_cost = send_transaction.value + gas_cost
    
        if sender_balance < total_cost:
            raise ValidationError("Sender account balance cannot afford txn. Sender balance = {}, total cost = {}".format(sender_balance, total_cost))

        # Send transaction nonces should always correspond to the nonce on this chain address. Not always going to be the sender.
        if account_db.get_nonce(this_chain_address) != send_transaction.nonce:
            raise ValidationError("Invalid send_transaction nonce. got: {0}, expected: {1}".format(send_transaction.nonce, account_db.get_nonce(send_transaction.sender)))


def validate_helios_testnet_transaction_against_header(_vm, base_header, send_transaction):
    if base_header.gas_used + send_transaction.gas > base_header.gas_limit:
        raise ValidationError(
            "send_transaction exceeds gas limit: using {}, bringing total to {}, but limit is {}".format(
                send_transaction.gas,
                base_header.gas_used + send_transaction.gas,
                base_header.gas_limit,
            )
        )
