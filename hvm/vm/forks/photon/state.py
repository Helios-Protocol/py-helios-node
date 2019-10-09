from __future__ import absolute_import
from typing import Type  # noqa: F401

from hvm import constants
from hvm.utils.address import generate_contract_address
from hvm.vm.forks.helios_testnet.validation import validate_helios_testnet_transaction
from hvm.vm.forks.photon.constants import REFUND_SELFDESTRUCT
from hvm.vm.forks.photon.validation import validate_photon_transaction
from hvm.vm.message import Message

from .account import PhotonAccountDB
from hvm.vm.forks.boson.state import BosonTransactionExecutor, BosonState

from .computation import PhotonComputation

from .transaction_context import PhotonTransactionContext

from .transactions import (
    PhotonTransaction,
    PhotonReceiveTransaction,
)
from typing import Union
from eth_utils import encode_hex
from eth_typing import Address
from typing import Optional
from eth_hash.auto import keccak

from .utils import photon_collect_touched_accounts
class PhotonTransactionExecutor(BosonTransactionExecutor):

    def build_evm_message(self,
                          send_transaction: PhotonTransaction,
                          transaction_context: PhotonTransactionContext,
                          receive_transaction: PhotonReceiveTransaction = None) -> Message:
        if transaction_context.is_refund == True:

            # Setup VM Message
            message_gas = 0
            refund_amount = receive_transaction.remaining_refund
            create_address = None
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

            # Setup VM Message
            message_gas = send_transaction.gas - send_transaction.intrinsic_gas

            refund_amount = 0

            if send_transaction.to == constants.CREATE_CONTRACT_ADDRESS:
                # create call
                # the contract address was already chosen on the send transaction. It is now the caller chain address
                create_address = transaction_context.this_chain_address
                data = b''
                code = send_transaction.data
            elif send_transaction.code_address == b'':
                # normal call
                create_address = None
                data = send_transaction.data
                code = self.vm_state.account_db.get_code(send_transaction.to)
            else:
                # surrogate call
                create_address = None
                data = send_transaction.data
                code = self.vm_state.account_db.get_code(send_transaction.code_address)

            self.vm_state.logger.debug(
                (
                    "RECEIVE TRANSACTION: hash: %s | sender: %s | to: %s | value: %s | gas: %s | "
                    "gas-price: %s | s: %s | r: %s | v: %s | data-hash: %s"
                ),
                encode_hex(send_transaction.hash),
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

            # transaction_context = self.get_transaction_context(send_transaction, receive_transaction)
            gas_fee = send_transaction.gas * transaction_context.gas_price

            # this is the default gas fee for the send tx that needs to be subtracted on the receive of a smart contract
            # Buy Gas
            self.vm_state.account_db.delta_balance(send_transaction.sender, -1 * gas_fee)

            # Increment Nonce
            self.vm_state.account_db.increment_nonce(send_transaction.sender)

            # Setup VM Message
            message_gas = send_transaction.gas - send_transaction.intrinsic_gas

            refund_amount = 0

            if send_transaction.to == constants.CREATE_CONTRACT_ADDRESS:
                # create call
                create_address = generate_contract_address(
                    send_transaction.sender,
                    self.vm_state.account_db.get_nonce(send_transaction.sender) - 1,
                )
                data = b''
                code = send_transaction.data
            elif send_transaction.code_address == b'':
                # normal call
                create_address = None
                data = send_transaction.data
                code = self.vm_state.account_db.get_code(send_transaction.to)
            else:
                # surrogate call
                create_address = None
                data = send_transaction.data
                code = self.vm_state.account_db.get_code(send_transaction.code_address)


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

        if send_transaction.created_by_computation:
            sender = send_transaction.caller
        else:
            sender = send_transaction.sender

        message = Message(
            gas=message_gas,
            to=send_transaction.to,
            sender=sender,
            value=send_transaction.value,
            data=data,
            code=code,
            create_address=create_address,
            refund_amount=refund_amount,
        )

        return message


    def get_transaction_context(self,
                                send_transaction: PhotonTransaction,
                                this_chain_address:Address,
                                receive_transaction: Optional[PhotonReceiveTransaction] = None,
                                refund_transaction: Optional[PhotonReceiveTransaction] = None) -> PhotonTransactionContext:

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

        if send_transaction.created_by_computation:
            origin = send_transaction.caller
        else:
            origin = send_transaction.sender

        return PhotonTransactionContext(
            send_tx_to = send_transaction.to,
            origin=origin,
            gas_price=send_transaction.gas_price,
            send_tx_hash=send_transaction.hash,
            this_chain_address = this_chain_address,
            is_receive=is_receive,
            is_refund=is_refund,
            receive_tx_hash=receive_transaction_hash,
            tx_caller = send_transaction.caller if send_transaction.caller != b'' else None,
            tx_origin = send_transaction.origin if send_transaction.origin != b'' else None,
            tx_code_address = send_transaction.code_address if send_transaction.code_address != b'' else None,
            tx_signer = send_transaction.sender,
            tx_execute_on_send=send_transaction.execute_on_send
        )

    def add_possible_refunds_to_currently_executing_transaction(self,
                                                                send_transaction: PhotonTransaction,
                                                                computation: PhotonComputation,
                                                                receive_transaction: PhotonReceiveTransaction = None,
                                                                refund_transaction: PhotonReceiveTransaction = None,
                                                                ) -> Union[PhotonTransaction, PhotonReceiveTransaction]:
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
            if computation.transaction_context.is_computation_call_origin or (computation.msg.data != b'' and not computation.msg.is_create):
                # New: we always process refunds after receiving a transaction originating in a computation call
                gas_refund_amount = computation.get_gas_remaining_including_refunds()

                self.vm_state.logger.debug(
                    'SAVING REFUND TO RECEIVE TX: %s -> %s',
                    gas_refund_amount,
                    encode_hex(computation.transaction_context.refund_address),
                )
                receive_transaction = receive_transaction.copy(remaining_refund=gas_refund_amount)

            return receive_transaction
        else:
            # this is a send transaction. Refunds are only possible on receive tx. So send it back unmodified
            return send_transaction


    def finalize_computation(self, send_transaction: PhotonTransaction, computation: PhotonComputation) -> PhotonComputation:
        #we only have to do any of this if it is a send transaction

        # Self Destruct Refunds
        num_deletions = len(computation.get_accounts_for_deletion())
        if num_deletions:
            computation.refund_gas(REFUND_SELFDESTRUCT * num_deletions)


        if computation.transaction_context.is_send and not computation.transaction_context.is_computation_call_origin:
            # this is a send transaction that didnt originate from a computation call. This is the only kind that could potentially refund gas

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
            touched_accounts = photon_collect_touched_accounts(computation)
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

    def validate_transaction(self,
                             send_transaction: PhotonTransaction,
                             this_chain_address: Address,
                             receive_transaction: Optional[PhotonReceiveTransaction] = None,
                             refund_transaction: Optional[PhotonReceiveTransaction] = None):

        # checks signature, gas, and field types
        send_transaction.validate()

        validate_photon_transaction(self.vm_state.account_db, send_transaction, this_chain_address, receive_transaction, refund_transaction)



class PhotonState(BosonState):
    computation_class: Type[PhotonComputation] = PhotonComputation
    transaction_executor: Type[PhotonTransactionExecutor] = PhotonTransactionExecutor
    account_db_class: Type[PhotonAccountDB] = PhotonAccountDB
    transaction_context_class: Type[PhotonTransactionContext] = PhotonTransactionContext

    account_db: PhotonAccountDB = None
    
