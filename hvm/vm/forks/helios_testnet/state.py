from __future__ import absolute_import
from typing import Type  # noqa: F401

from eth_hash.auto import keccak

from hvm import constants
from hvm.db.account import (
    AccountDB,
)
from hvm.exceptions import (
    ContractCreationCollision,
    ValidationError,
)
from hvm.vm.message import (
    Message,
)
from hvm.vm.state import (
    BaseState,
    BaseTransactionExecutor,
)

from hvm.utils.address import (
    generate_contract_address,
)
from hvm.utils.hexadecimal import (
    encode_hex,
)

from .constants import REFUND_SELFDESTRUCT

from .validation import validate_helios_testnet_transaction

from hvm.rlp.transactions import (
    BaseTransaction,
    BaseReceiveTransaction
)

from .computation import HeliosTestnetComputation

from .transaction_context import (  # noqa: F401
    BaseTransactionContext,
    HeliosTestnetTransactionContext
)

from .utils import collect_touched_accounts

from typing import Union  # noqa: F401
   
class HeliosTestnetTransactionExecutor(BaseTransactionExecutor):
        
    def get_transaction_context(self, send_transaction: BaseTransaction, receive_transaction: Union[BaseReceiveTransaction, type(None)] = None):
        #for sending transactions, we won't know the sender block hash until after all transactions 
        #have been processed and the block is finalized. So:
        #TODO: save all sending transactions to receivable database later as block is finalized
        #however, we can process receive transactions fully
        if receive_transaction is None:
            is_receive = False
        else:
            is_receive = True

        return self.vm_state.get_transaction_context_class()(
            origin=send_transaction.sender,
            gas_price=send_transaction.gas_price,
            send_tx_hash=send_transaction.hash,
            is_receive=is_receive,
        )
            
    def validate_transaction(self, send_transaction: BaseTransaction, caller_chain_address:bytes, receive_transaction: Union[BaseReceiveTransaction, type(None)] = None):
        # going to put all validation here instead of all over the place.
        # Validate the transaction
        
        # this is already done with transaction.validate
        #if transaction.intrinsic_gas > transaction.gas:
        #    raise ValidationError("Insufficient gas")

        #checks signature, gas, and field types
        send_transaction.validate()

        #for sending: checks that sender has enough funds.
        #for receiving: checks that the receiving tx is in the state, also checks that the 
        #receiving tx sender hash matches the real sender hash. This also gaurantees that the sender
        #sent the tx to this receiver, because the hash matches the one in the state
        validate_helios_testnet_transaction(self.vm_state.account_db, send_transaction, caller_chain_address, receive_transaction)


    def build_evm_message(self, send_transaction: BaseTransaction, transaction_context):
        if transaction_context.is_receive == False:
            #if it is a receive transaction where receiver is a smart contract, then it needs to include gas.
            #if this is the case, it can use the gas, and gas_price from transaction.transaction
            #if the receive transaction runs out of gas, it needs to be allowed to stay on the blockchain and
            #initiate a send transaction that sends the remaining funds back to the sender. This will stop
            #a sender from DOSing by constantly re-trying the receive part of a transaction that fails because
            #it doesnt have enough gas.
            #IMPORTANT: on all receive transactions that go to smart contracts, subtract the send transaction fee
            #from the gas limit before doing computation.
            #also, if a send transaction is sent to a smart contract, we have to remove all computation fees
            #except for the transfer computation fee. But we still need to calculate the computation fees
            #to ensure that it has enough gas to do the computation once the receive tx is added.
            #if receive_transaction is None:

            #transaction_context = self.get_transaction_context(send_transaction, receive_transaction)
            gas_fee = send_transaction.gas * transaction_context.gas_price

            #this is the default gas fee for the send tx that needs to be subtracted on the receive of a smart contract
            # Buy Gas
            self.vm_state.account_db.delta_balance(send_transaction.sender, -1 * gas_fee)

            # Increment Nonce
            self.vm_state.account_db.increment_nonce(send_transaction.sender)

            # Setup VM Message
            message_gas = send_transaction.gas - send_transaction.intrinsic_gas

            #when a contract is created with a send transaction, do no computation.
            #we have to put the computation back. because it needs to charge computation
            #gas on the send. We just have to make sure it doesnt execute the transaction...
            #TODO: make sure the computation is not executed
            #temporarily we will just do no computation. This means interactions with
            #smart contracts will cost no gas until we finish this.
            contract_address = None
            data = b''
            code = b''

    #            if transaction.to == constants.CREATE_CONTRACT_ADDRESS:
    #                contract_address = generate_contract_address(
    #                    transaction.sender,
    #                    self.vm_state.account_db.get_nonce(transaction.sender) - 1,
    #                )
    #                data = b''
    #                code = transaction.data
    #            else:
    #                contract_address = None
    #                data = transaction.data
    #                code = self.vm_state.account_db.get_code(transaction.to)

            self.vm_state.logger.debug(
                (
                    "SEND TRANSACTION: sender: %s | to: %s | value: %s | gas: %s | "
                    "gas-price: %s | s: %s | r: %s | v: %s | data-hash: %s"
                ),
                encode_hex(send_transaction.sender),
                encode_hex(send_transaction.to),
                send_transaction.value,
                send_transaction.gas,
                send_transaction.gas_price,
                send_transaction.s,
                send_transaction.r,
                send_transaction.v,
                encode_hex(keccak(send_transaction.data)),
            )

            message = Message(
                gas=message_gas,
                to=send_transaction.to,
                sender=send_transaction.sender,
                value=send_transaction.value,
                data=data,
                code=code,
                create_address=contract_address,
            )
            return message
        
        else:
            #this is a receive transaction - now we get to execute any code or data
            #transaction_context = self.get_transaction_context(send_transaction)
            #gas_fee = transaction.transaction.gas * transaction_context.gas_price

            # TODO:
            # fail niceley here so we can put a failed tx. the failed tx can be seen in the receipt status_code
            # we will have to refund the sender the money if this is the case.
            # so the amount of gas the send tx paid is saved as transaction.transaction.gas
            # Setup VM Message
            #message_gas = transaction.transaction.gas - transaction.transaction.intrinsic_gas -1 * gas_fee
            # I tested this, if this tx uses more gas than what was charged to the send tx it will fail.
            contract_address = None
            data = b''
            code = b''

            # if transaction.transaction.to == constants.CREATE_CONTRACT_ADDRESS:
            #     contract_address = generate_contract_address(
            #         transaction.sender,
            #         self.vm_state.account_db.get_nonce(transaction.sender) - 1,
            #     )
            #     data = b''
            #     code = transaction.transaction.data
            # else:
            #     contract_address = None
            #     data = transaction.transaction.data
            #     code = self.vm_state.account_db.get_code(transaction.transaction.to)

            self.vm_state.logger.debug(
                (
                    "RECEIVE TRANSACTION: sender: %s | to: %s | value: %s | gas: %s | "
                    "gas-price: %s | s: %s | r: %s | v: %s | data-hash: %s"
                ),
                encode_hex(send_transaction.sender),
                encode_hex(send_transaction.to),
                send_transaction.value,
                send_transaction.gas,
                send_transaction.gas_price,
                send_transaction.s,
                send_transaction.r,
                send_transaction.v,
                encode_hex(keccak(data)),
            )

            message = Message(
                gas=0,
                to=send_transaction.to,
                sender=send_transaction.sender,
                value=send_transaction.value,
                data=data,
                code=code,
                create_address=contract_address,
            )
            return message

    def build_computation(self, message, transaction_context, validate = True):
        #TODO: here to have to make sure that the smart contract only sends funds from itself...
        """Apply the message to the VM."""
        if message.is_create:
            is_collision = self.vm_state.account_db.account_has_code_or_nonce(
                message.storage_address
            )

            if is_collision:
                # The address of the newly created contract has *somehow* collided
                # with an existing contract address.
                computation = self.vm_state.get_computation(message, transaction_context)
                computation._error = ContractCreationCollision(
                    "Address collision while creating contract: {0}".format(
                        encode_hex(message.storage_address),
                    )
                )
                self.vm_state.logger.debug(
                    "Address collision while creating contract: %s",
                    encode_hex(message.storage_address),
                )
            else:
                computation = self.vm_state.get_computation(
                    message,
                    transaction_context,
                ).apply_create_message()
        else:
            computation = self.vm_state.get_computation(
                message,
                transaction_context).apply_message(validate=validate)

        return computation

      
    def finalize_computation(self, send_transaction: BaseTransaction, transaction_context, computation):
        #we only have to do any of this if it is a send transaction
        if not transaction_context.is_receive:
            # Self Destruct Refunds
            num_deletions = len(computation.get_accounts_for_deletion())
            if num_deletions:
                computation.refund_gas(REFUND_SELFDESTRUCT * num_deletions)

            # Gas Refunds
            gas_remaining = computation.get_gas_remaining()
            gas_refunded = computation.get_gas_refund()

            gas_used = send_transaction.gas - gas_remaining
            gas_refund = min(gas_refunded, gas_used // 2)
            gas_refund_amount = (gas_refund + gas_remaining) * send_transaction.gas_price

            if gas_refund_amount:
                self.vm_state.logger.debug(
                    'TRANSACTION REFUND: %s -> %s',
                    gas_refund_amount,
                    encode_hex(computation.msg.sender),
                )

                self.vm_state.account_db.delta_balance(computation.msg.sender, gas_refund_amount)

            # Miner Fees
            transaction_fee = \
                (send_transaction.gas - gas_remaining - gas_refund) * send_transaction.gas_price
            self.vm_state.logger.debug(
                'BURNING TRANSACTION FEE: %s',
                transaction_fee,
            )

            # Process Self Destructs
            for account, beneficiary in computation.get_accounts_for_deletion():
                # TODO: need to figure out how we prevent multiple selfdestructs from
                # the same account and if this is the right place to put this.
                self.vm_state.logger.debug('DELETING ACCOUNT: %s', encode_hex(account))

                # TODO: this balance setting is likely superflous and can be
                # removed since `delete_account` does this.
                self.vm_state.account_db.set_balance(account, 0)
                self.vm_state.account_db.delete_account(account)
            
        
            #
            # EIP161 state clearing
            #
            touched_accounts = collect_touched_accounts(computation)
            for account in touched_accounts:
                should_delete = (
                    self.vm_state.account_db.account_exists(account) and
                    self.vm_state.account_db.account_is_empty(account)
                )
                if should_delete:
                    self.vm_state.logger.debug(
                        "CLEARING EMPTY ACCOUNT: %s",
                        encode_hex(account),
                    )
                    self.vm_state.account_db.delete_account(account)
    
        return computation


class HeliosTestnetState(BaseState):
    computation_class = HeliosTestnetComputation
    transaction_executor = HeliosTestnetTransactionExecutor  # Type[BaseTransactionExecutor]
    account_db_class = AccountDB  # Type[BaseAccountDB]
    transaction_context_class = HeliosTestnetTransactionContext  # type: Type[BaseTransactionContext]
    
