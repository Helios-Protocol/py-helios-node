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

from eth_typing import Address, Hash32
from .computation import HeliosTestnetComputation

from .transaction_context import (  # noqa: F401
    BaseTransactionContext,
    HeliosTestnetTransactionContext
)

from .utils import collect_touched_accounts

from typing import Union, Optional, TYPE_CHECKING  # noqa: F401

if TYPE_CHECKING:
    from hvm.vm.computation import (  # noqa: F401
        BaseComputation,
    )


class HeliosTestnetTransactionExecutor(BaseTransactionExecutor):
        
    def get_transaction_context(self,
                                send_transaction: BaseTransaction,
                                caller_chain_address:Address,
                                receive_transaction: Optional[BaseReceiveTransaction] = None,
                                refund_transaction: Optional[BaseReceiveTransaction] = None) -> BaseTransactionContext:
        #for sending transactions, we won't know the sender block hash until after all transactions 
        #have been processed and the block is finalized. So:
        #TODO: save all sending transactions to receivable database later as block is finalized
        #however, we can process receive transactions fully
        if receive_transaction is None:
            is_receive = False
            receive_transaction_hash = None
        else:
            is_receive = True
            receive_transaction_hash = receive_transaction.hash

        if refund_transaction is None:
            is_refund = False
        else:
            is_refund = True

        return self.vm_state.get_transaction_context_class()(
            origin=send_transaction.sender,
            gas_price=send_transaction.gas_price,
            send_tx_hash=send_transaction.hash,
            caller_chain_address = caller_chain_address,
            is_receive=is_receive,
            is_refund=is_refund,
            receive_tx_hash=receive_transaction_hash,
        )
            
    def validate_transaction(self, send_transaction: BaseTransaction, caller_chain_address:Address, receive_transaction: Optional[BaseReceiveTransaction] = None, refund_transaction: Optional[BaseReceiveTransaction] = None):
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
        validate_helios_testnet_transaction(self.vm_state.account_db, send_transaction, caller_chain_address, receive_transaction, refund_transaction)


    def build_evm_message(self,
                          send_transaction: BaseTransaction,
                          transaction_context: BaseTransactionContext,
                          receive_transaction: BaseReceiveTransaction = None) -> Message:
        if transaction_context.is_refund == True:

            # Setup VM Message
            message_gas = 0

            refund_amount = receive_transaction.remaining_refund

            contract_address = None
            data = b''
            code = b''

            self.vm_state.logger.debug(
                (
                    "REFUND TRANSACTION: sender: %s | refund amount: %s "
                ),
                encode_hex(send_transaction.sender),
                refund_amount,
            )

        elif transaction_context.is_receive == True:
            # this is a receive transaction - now we get to execute any code or data
            # transaction_context = self.get_transaction_context(send_transaction)
            # gas_fee = transaction.transaction.gas * transaction_context.gas_price

            # TODO:
            # fail niceley here so we can put a failed tx. the failed tx can be seen in the receipt status_code
            # we will have to refund the sender the money if this is the case.
            # so the amount of gas the send tx paid is saved as transaction.transaction.gas
            # Setup VM Message
            # message_gas = transaction.transaction.gas - transaction.transaction.intrinsic_gas -1 * gas_fee
            # I tested this, if this tx uses more gas than what was charged to the send tx it will fail.


            # Setup VM Message
            message_gas = send_transaction.gas - send_transaction.intrinsic_gas

            refund_amount = 0

            if send_transaction.to == constants.CREATE_CONTRACT_ADDRESS:
                # the contract address was already chosen on the send transaction. It is now the caller chain address
                contract_address = transaction_context.caller_chain_address
                data = b''
                code = send_transaction.data
            else:
                contract_address = None
                data = send_transaction.data
                code = self.vm_state.account_db.get_code(send_transaction.to)

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

        else:
            # this is a send transaction

            #transaction_context = self.get_transaction_context(send_transaction, receive_transaction)
            gas_fee = send_transaction.gas * transaction_context.gas_price

            #this is the default gas fee for the send tx that needs to be subtracted on the receive of a smart contract
            # Buy Gas
            self.vm_state.account_db.delta_balance(send_transaction.sender, -1 * gas_fee)

            # Increment Nonce
            self.vm_state.account_db.increment_nonce(send_transaction.sender)

            # Setup VM Message
            message_gas = send_transaction.gas - send_transaction.intrinsic_gas

            refund_amount = 0

            #when a contract is created with a send transaction, do no computation.
            #we have to put the computation back. because it needs to charge computation
            #gas on the send. We just have to make sure it doesnt execute the transaction...
            #TODO: make sure the computation is not executed
            #temporarily we will just do no computation. This means interactions with
            #smart contracts will cost no gas until we finish this.

            if send_transaction.to == constants.CREATE_CONTRACT_ADDRESS:
                contract_address = generate_contract_address(
                    send_transaction.sender,
                    self.vm_state.account_db.get_nonce(send_transaction.sender) - 1,
                )
                data = b''
                code = send_transaction.data
            else:
                contract_address = None
                data = send_transaction.data
                code = self.vm_state.account_db.get_code(send_transaction.to)

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
            refund_amount=refund_amount,
        )
        return message



    def build_computation(self, message: Message, transaction_context: BaseTransactionContext, validate: bool = True) -> 'BaseComputation':
        """Apply the message to the VM."""

        if transaction_context.is_refund:
            computation = self.vm_state.get_computation(
                message,
                transaction_context).apply_message(validate=validate)

        else:
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
                    ).apply_create_message(validate=validate)
            else:
                computation = self.vm_state.get_computation(
                    message,
                    transaction_context).apply_message(validate=validate)

        return computation

      
    def finalize_computation(self, send_transaction: BaseTransaction, computation: 'BaseComputation') -> 'BaseComputation':
        #we only have to do any of this if it is a send transaction

        # Self Destruct Refunds
        num_deletions = len(computation.get_accounts_for_deletion())
        if num_deletions:
            computation.refund_gas(REFUND_SELFDESTRUCT * num_deletions)


        if not computation.transaction_context.is_receive and not computation.transaction_context.is_refund:
            # this is a send transaction. This is the only kind that could potentially refund gas

            if computation.msg.is_create or computation.msg.data == b'':
                # We are deploying a smart contract, we pay all computation fees now and refund leftover gas
                # OR
                # This transaction has no computation. It is just a HLS transaction. Send the transaction and refund leftover gas

                gas_remaining = computation.get_gas_remaining()
                gas_refunded = computation.get_gas_refund()

                gas_used = send_transaction.gas - gas_remaining
                gas_refund = min(gas_refunded, gas_used // 2)
                gas_refund_amount = (gas_refund + gas_remaining) * send_transaction.gas_price

                if gas_refund_amount:
                    self.vm_state.logger.debug(
                        'GAS REFUND: %s -> %s',
                        gas_refund_amount,
                        encode_hex(computation.msg.sender),
                    )

                    self.vm_state.account_db.delta_balance(computation.msg.sender, gas_refund_amount)

                # In order to keep the state consistent with the block headers, we want the newly created smart contract chain
                # to have an empty state. The smart contract data will be stored when the recieve transaction is executed.
                # At that time, the smart contract state can also be saved in the block header to keep the local state and
                # block header state consistent at all times.

                # This is also in line with the policy to only run computation on recieve transactions.

        if computation.transaction_context.is_receive and not computation.transaction_context.is_refund:
            # This is a receive transaction. This is the only kind that can process computations.
            # So this is the only case where we need to clean up stuff
            # Process Self Destructs
            for account, beneficiary in computation.get_accounts_for_deletion():
                # TODO: need to figure out how we prevent multiple selfdestructs from
                # the same account and if this is the right place to put this.
                self.vm_state.logger.debug('DELETING ACCOUNT: %s', encode_hex(account))

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

    def add_possible_refunds_to_currently_executing_transaction(self,
                            send_transaction: BaseTransaction,
                            computation: 'BaseComputation',
                            receive_transaction: BaseReceiveTransaction = None,
                            refund_transaction: BaseReceiveTransaction = None,
                            ) -> Union[BaseTransaction, BaseReceiveTransaction]:
        '''
        Receive transactions that have computation will have to refund any leftover gas. This refund amount depends
        on the computation which is why it is processed here and added the receive tx.

        :param send_transaction:
        :param computation:
        :param receive_transaction:
        :param refund_transaction:
        :return:
        '''
        if computation.transaction_context.is_refund:
            # this kind of receive transaction will always have 0 remaining refund so it doesnt need to be modified
            return refund_transaction

        elif computation.transaction_context.is_receive:
            # this kind of receive transaction may include a nonzero gas refund. Must add it in now
            # It gets a refund if send has data and is not create. ie. there was a computation on receive
            if computation.msg.data != b'' and not computation.msg.is_create:
                gas_remaining = computation.get_gas_remaining()
                gas_refunded = computation.get_gas_refund()

                gas_used = send_transaction.gas - gas_remaining
                gas_refund = min(gas_refunded, gas_used // 2)
                gas_refund_amount = (gas_refund + gas_remaining) * send_transaction.gas_price

                self.vm_state.logger.debug(
                    'SAVING REFUND TO RECEIVE TX: %s -> %s',
                    gas_refund_amount,
                    encode_hex(computation.msg.sender),
                )
                receive_transaction = receive_transaction.copy(remaining_refund = gas_refund_amount)

            return receive_transaction
        else:
            #this is a send transaction. Refunds are only possible on receive tx. So send it back unmodified
            return send_transaction




class HeliosTestnetState(BaseState):
    computation_class = HeliosTestnetComputation
    transaction_executor = HeliosTestnetTransactionExecutor  # Type[BaseTransactionExecutor]
    account_db_class = AccountDB  # Type[BaseAccountDB]
    transaction_context_class = HeliosTestnetTransactionContext  # type: Type[BaseTransactionContext]
    
