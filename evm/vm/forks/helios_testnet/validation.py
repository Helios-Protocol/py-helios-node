from evm.exceptions import (
    ValidationError,
    ReceiveTransactionIncorrectSenderBlockHash,
    ReceivableTransactionNotFound,
    ReceivingTransactionForWrongWallet,
)
from evm.constants import (
    SECPK1_N,
)
from evm.rlp.transactions import (
    BaseTransaction,
    BaseReceiveTransaction 
)

'''
This only performs checks that can be done against the state.
'''
   
def validate_helios_testnet_transaction(account_db, transaction):
    if transaction.s > SECPK1_N // 2 or transaction.s == 0:
        raise ValidationError("Invalid signature S value")
        
    #first find out if it is a send transaction or a receive transaction
    if isinstance(transaction, BaseReceiveTransaction):
        # if it is a receive transaction we need to make sure the send transaction exists and is within the correct block hash
        #TODO: need to check to see if transaction hash already exists in our db. this will stop double receive. 
        #TODO: dont forget to delete the receivable transaction after executing
        receiver = transaction.receiver 
        receivable_tx_key = account_db.get_receivable_transaction(receiver, transaction.transaction.hash)
        
        if receivable_tx_key is False:
            raise ReceivableTransactionNotFound("The receive transaction is not in our db")
        if transaction.sender_block_hash != receivable_tx_key.sender_block_hash:
            raise ReceiveTransactionIncorrectSenderBlockHash("The receive transaction sender block hash doesn't match the one in our db")
    

    else:
        gas_cost = transaction.gas * transaction.gas_price
        sender_balance = account_db.get_balance(transaction.sender)
    
        if sender_balance < gas_cost:
            raise ValidationError(
                "Sender account balance cannot afford txn gas: `{0}`".format(transaction.sender)
            )
    
        total_cost = transaction.value + gas_cost
    
        if sender_balance < total_cost:
            raise ValidationError("Sender account balance cannot afford txn")
    
        if account_db.get_nonce(transaction.sender) != transaction.nonce:
            raise ValidationError("Invalid transaction nonce. got: {0}, expected: {1}".format(transaction.nonce, account_db.get_nonce(transaction.sender)))


def validate_helios_testnet_transaction_against_header(_vm, base_header, transaction):
    if isinstance(transaction, BaseTransaction):
        if base_header.gas_used + transaction.gas > base_header.gas_limit:
            raise ValidationError(
                "Transaction exceeds gas limit: using {}, bringing total to {}, but limit is {}".format(
                    transaction.gas,
                    base_header.gas_used + transaction.gas,
                    base_header.gas_limit,
                )
            )
