from hvm.exceptions import (
    ValidationError,
    ReceiveTransactionIncorrectSenderBlockHash,
    ReceivableTransactionNotFound,
    ReceivingTransactionForWrongWallet,
)
from hvm.constants import (
    SECPK1_N,
    CREATE_CONTRACT_ADDRESS
)
from hvm.rlp.transactions import (
    BaseTransaction,
    BaseReceiveTransaction 
)
from typing import Union, Optional # noqa: F401

'''
This only performs checks that can be done against the state.
'''
   
def validate_helios_testnet_transaction(account_db, send_transaction: BaseTransaction, caller_chain_address:bytes, receive_transaction: Optional[BaseReceiveTransaction] = None, refund_receive_transaction: Optional[BaseReceiveTransaction] = None):

    #first find out if it is a send send_transaction or a receive transaction or a refund transaction
    if refund_receive_transaction is not None:
        #this is a refund transaction
        if refund_receive_transaction.is_refund is False:
            raise ValidationError(
                'Only refund transactions can be used for a refund. On this transaction is_from_refund = False.')

        if refund_receive_transaction.remaining_refund != 0:
            raise ValidationError(
                'Refund transactions must have 0 remaining refund')

        if send_transaction.sender != caller_chain_address:
            raise ValidationError(
                'Refunds can only go back to the original chain that sent the initial transaction')

    elif receive_transaction is not None:
        #this is a receive transaction
        # if it is a receive send_transaction we need to make sure the send send_transaction exists and is within the correct block hash
        #TODO: need to check to see if send_transaction hash already exists in our db. this will stop double receive. answer: This is done in the vm before it gets here
        #TODO: dont forget to delete the receivable send_transaction after executing. answer:done
        #we check to make sure the send transaction is in the account in the state before it gets here.
        #receiver = send_transaction.receiver

        if send_transaction.to != caller_chain_address and send_transaction.to != CREATE_CONTRACT_ADDRESS:
            raise ValidationError(
                'Receive transaction is trying to receive a transaction that is not meant for this chain')

        if receive_transaction.is_refund is True:
            raise ValidationError(
                'The receive transaction is incorrectly marked as a refund.')

    else:
        #this is a send transaction
        if send_transaction.s > SECPK1_N // 2 or send_transaction.s == 0:
            raise ValidationError("Invalid signature S value")

        #this is just a normal send transaction
        if send_transaction.sender != caller_chain_address:
            raise ValidationError(
                'Send transaction sender doesnt match the caller_chain_address. If sending a tx, it must be sent by the sender chain address. Transaction sender = {}, caller_chain_address = {}'
                    .format(send_transaction.sender, caller_chain_address))

        gas_cost = send_transaction.gas * send_transaction.gas_price
        sender_balance = account_db.get_balance(send_transaction.sender)
    
        if sender_balance < gas_cost:
            raise ValidationError(
                "Sender account balance cannot afford txn gas. Balance:{}, gas cost: {}".format(sender_balance, gas_cost)
            )
    
        total_cost = send_transaction.value + gas_cost
    
        if sender_balance < total_cost:
            raise ValidationError("Sender account balance cannot afford txn. Sender balance = {}, total cost = {}".format(sender_balance, total_cost))
    
        if account_db.get_nonce(send_transaction.sender) != send_transaction.nonce:
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
