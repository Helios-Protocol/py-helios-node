from hvm.exceptions import (
    ValidationError,
    ReceiveTransactionIncorrectSenderBlockHash,
    ReceivableTransactionNotFound,
    ReceivingTransactionForWrongWallet,
)
from hvm.constants import (
    SECPK1_N,
)
from hvm.rlp.transactions import (
    BaseTransaction,
    BaseReceiveTransaction 
)
from typing import Union  # noqa: F401

'''
This only performs checks that can be done against the state.
'''
   
def validate_helios_testnet_transaction(account_db, send_transaction: BaseTransaction, caller_chain_address:bytes, receive_transaction: Union[BaseReceiveTransaction, type(None)] = None):

    #first find out if it is a send send_transaction or a receive transaction
    if receive_transaction is not None:
        # if it is a receive send_transaction we need to make sure the send send_transaction exists and is within the correct block hash
        #TODO: need to check to see if send_transaction hash already exists in our db. this will stop double receive. answer: This is done in the vm before it gets here
        #TODO: dont forget to delete the receivable send_transaction after executing. answer:done
        #we check to make sure the send transaction is in the account in the state before it gets here.
        #receiver = send_transaction.receiver

        if send_transaction.to != caller_chain_address:
            raise ValidationError(
                'Receive transaction is trying to receive a transaction that is not meant for this chain')

    else:
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
                "Sender account balance cannot afford txn gas: `{0}`".format(send_transaction.sender)
            )
    
        total_cost = send_transaction.value + gas_cost
    
        if sender_balance < total_cost:
            raise ValidationError("Sender account balance cannot afford txn")
    
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
