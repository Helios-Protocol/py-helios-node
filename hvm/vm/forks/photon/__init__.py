from eth_typing import Hash32, Address
from eth_utils import encode_hex

from hvm.constants import BLOCK_GAS_LIMIT, COMPUTATION_CALL_SEND_TRANSACTION_RECURSION_DEPTH_LIMIT
from hvm.exceptions import ValidationError
from hvm.utils.address import generate_contract_address
from hvm.utils.rlp import diff_rlp_object
from hvm.utils.spoof import SpoofTransaction
from hvm.vm.forks.photon.consensus import PhotonConsensusDB
from hvm.vm.forks.photon.utils import ensure_computation_call_send_transactions_are_equal
from hvm.vm.message import Message

from .constants import (
    EIP658_TRANSACTION_STATUS_CODE_FAILURE,
    EIP658_TRANSACTION_STATUS_CODE_SUCCESS,
)

from .validation import validate_photon_transaction_against_header

from .blocks import (
    PhotonBlock, PhotonQueueBlock, PhotonMicroBlock)

from .headers import (create_photon_header_from_parent, configure_photon_header)
from .state import PhotonState
from hvm.vm.base import VM

from hvm.rlp.receipts import (
    Receipt,
)

from .transactions import (
    PhotonTransaction,
    PhotonReceiveTransaction,
)

from .computation import PhotonComputation

from hvm.rlp.headers import BaseBlockHeader, BlockHeader

from hvm.vm.forks.boson import make_boson_receipt

from typing import Tuple, List, Optional

from eth_bloom import (
    BloomFilter,
)

import functools

from eth_keys.datatypes import PrivateKey

def make_photon_receipt(base_header: BaseBlockHeader,
                                computation: PhotonComputation,
                                send_transaction: PhotonTransaction,
                                receive_transaction: PhotonReceiveTransaction = None,
                                refund_transaction: PhotonReceiveTransaction = None,
                                ) -> Receipt:

    return make_boson_receipt(base_header,
                                       computation,
                                       send_transaction,
                                       receive_transaction,
                                       refund_transaction)


class PhotonVM(VM):
    # fork name
    fork = 'photon'

    # classes
    micro_block_class = PhotonMicroBlock
    block_class = PhotonBlock
    queue_block_class = PhotonQueueBlock
    _state_class = PhotonState

    # Methods
    create_header_from_parent = staticmethod(create_photon_header_from_parent)
    configure_header = configure_photon_header
    make_receipt = staticmethod(make_photon_receipt)
    validate_transaction_against_header = validate_photon_transaction_against_header
    consensus_db_class = PhotonConsensusDB

    min_time_between_blocks = constants.MIN_TIME_BETWEEN_BLOCKS

    def generate_transaction_for_single_computation(self,
                                                    tx_data: bytes,
                                                    from_address: Address,
                                                    to_address: Address,
                                                    **kwargs,
                                                    ) -> SpoofTransaction:
        tx_nonce = self.state.account_db.get_nonce(from_address)
        if from_address == self.header.chain_address:
            # This chain is the from address, so it should be execute on send
            execute_on_send = True
        else:
            execute_on_send = False

        transaction = self.create_transaction(
            gas_price=0x00,
            gas=BLOCK_GAS_LIMIT,
            to=to_address,
            value=0,
            nonce=tx_nonce,
            data=tx_data,
            execute_on_send = execute_on_send,
            **kwargs,
        )

        return SpoofTransaction(transaction, from_=from_address)


    def create_computation_call_transactions_from_finished_computations(self,
                                                                        finished_computations: List[PhotonComputation],
                                                                        block: PhotonBlock,
                                                                        current_nonce_for_computation_calls: int = None,
                                                                        private_key_for_signing: PrivateKey = None) -> Tuple[List[PhotonTransaction], Optional[int]]:

        computation_call_send_transactions = []
        for computation in finished_computations:

            if computation.transaction_context.has_data and not computation.is_error:

                # Only check if there is actually transaction data because this will be an expensive function
                external_call_messages = computation.get_all_children_external_call_messages()

                if len(external_call_messages) > 0:
                    # Do this in here for performance. We only compute it if there are computation calls.
                    if current_nonce_for_computation_calls is None:
                        current_nonce_for_computation_calls = self.get_nonce_for_computation_calls(block)

                    for i in range(len(external_call_messages)):
                        call_message = external_call_messages[i]

                        if call_message.is_create:
                            self.validate_create_call(call_message, current_nonce_for_computation_calls)

                        new_tx = self.create_transaction(
                            nonce = current_nonce_for_computation_calls,
                            gas_price=computation.transaction_context.gas_price,
                            gas=call_message.gas,
                            to=call_message.to,
                            value=call_message.value,
                            data=call_message.data_as_bytes,
                            caller = block.header.chain_address,
                            origin = computation.transaction_context.child_tx_origin,
                            code_address = call_message.child_tx_code_address,
                            create_address = call_message.child_tx_create_address,
                            execute_on_send = call_message.execute_on_send
                        )

                        self.logger.debug("Creating a new child transaction with parameters:"
                                          "nonce: {} | gas_price: {} | gas: {} | to: {} | "
                                          "value: {} | data: {} | "
                                          "caller: {} | origin: {} | "
                                          "code_address: {} | execute_on_send: {}".format(
                            new_tx.nonce, new_tx.gas_price, new_tx.gas, encode_hex(new_tx.to),
                            new_tx.value, encode_hex(new_tx.data), encode_hex(new_tx.caller),
                            encode_hex(new_tx.origin), encode_hex(new_tx.code_address), new_tx.execute_on_send
                        ))

                        if private_key_for_signing is not None:
                            # sign it only if a private key was given. Otherwise, this is not a queueblock
                            new_tx = new_tx.get_signed(private_key_for_signing, self.network_id)

                        computation_call_send_transactions.append(new_tx)

                        current_nonce_for_computation_calls += 1

        return computation_call_send_transactions, current_nonce_for_computation_calls


    def choose_which_transactions_to_apply(self,
                                           computation_call_send_transactions: List[PhotonTransaction],
                                           block_computation_call_send_transactions_remaining: List[PhotonTransaction] = [],
                                           private_key: PrivateKey = None) -> Tuple[List[PhotonTransaction], List[PhotonTransaction]]:

        if len(computation_call_send_transactions) != 0 and len(block_computation_call_send_transactions_remaining) == 0:
            if private_key is None:
                raise ValidationError("The block doesn't have the send transactions generated by the compuation call. "
                                      "If this is a queue block, then you must provide a private key for signing")
            # They have been signed, lets add them to the list
            send_transactions_to_apply = computation_call_send_transactions
        else:
            send_transactions_to_apply = block_computation_call_send_transactions_remaining[:len(computation_call_send_transactions)]
            block_computation_call_send_transactions_remaining = block_computation_call_send_transactions_remaining[len(computation_call_send_transactions):]

        return send_transactions_to_apply, block_computation_call_send_transactions_remaining

        

    def apply_all_transactions(self, block: PhotonBlock, private_key: PrivateKey = None, is_queue_block = False) -> Tuple[
                                                                                        BaseBlockHeader,
                                                                                        List[Receipt],
                                                                                        List[PhotonComputation],
                                                                                        List[PhotonComputation],
                                                                                        List[PhotonTransaction],
                                                                                        List[PhotonReceiveTransaction]]:
            

        # First, run all of the receive transactions
        last_header, receive_receipts, receive_computations, processed_receive_transactions = self._apply_all_receive_transactions(block.receive_transactions, block.header, is_queue_block = is_queue_block)

        computation_call_send_transactions, current_nonce_for_computation_calls = self.create_computation_call_transactions_from_finished_computations(
            receive_computations,
            block,
            None,
            private_key
        )

        # Variables to hold the totals
        all_computation_call_send_transactions = computation_call_send_transactions
        send_receipts = []
        all_send_computations = []

        block_normal_send_transactions, block_computation_call_send_transactions = self.separate_normal_transactions_and_computation_calls(block.transactions)

        computation_call_send_transactions_to_apply, block_computation_call_send_transactions_remaining = self.choose_which_transactions_to_apply(
                   computation_call_send_transactions,
                   block_computation_call_send_transactions,
                   private_key
            )

        send_transactions_to_apply = block_normal_send_transactions
        send_transactions_to_apply.extend(computation_call_send_transactions_to_apply)


        for i in range(COMPUTATION_CALL_SEND_TRANSACTION_RECURSION_DEPTH_LIMIT):
            # Then, run all of the send_transactions_to_apply
            self.logger.debug("Applying send transactions with recursion depth {}".format(i))
            last_header, receipts, send_computations = self._apply_all_send_transactions(send_transactions_to_apply, last_header)

            send_receipts.extend(receipts)
            all_send_computations.extend(send_computations)

            computation_call_send_transactions, current_nonce_for_computation_calls = self.create_computation_call_transactions_from_finished_computations(
                send_computations,
                block,
                current_nonce_for_computation_calls,
                private_key
            )

            all_computation_call_send_transactions.extend(computation_call_send_transactions)

            send_transactions_to_apply, block_computation_call_send_transactions_remaining = self.choose_which_transactions_to_apply(
                   computation_call_send_transactions,
                   block_computation_call_send_transactions_remaining,
                   private_key
            )


            if len(send_transactions_to_apply) == 0:
                break

        # Combine receipts in the send transaction, receive transaction order
        send_receipts.extend(receive_receipts)

        return last_header, send_receipts, receive_computations, all_send_computations, all_computation_call_send_transactions, processed_receive_transactions

    def save_recievable_transactions(self,
                                     block_header_hash: Hash32,
                                     send_computations: List[PhotonComputation],
                                     receive_computations: List[PhotonComputation]) -> None:

        for computation in send_computations:
            msg = computation.msg
            transaction_context = computation.transaction_context
            if not computation.is_error:
                self.state.account_db.add_receivable_transaction(msg.resolved_to,
                                                                 transaction_context.send_tx_hash,
                                                                 block_header_hash,
                                                                 msg.is_create)

        for computation in receive_computations:
            # Process refunds here
            if computation.transaction_context.is_receive and not computation.transaction_context.is_refund:
                # this kind of receive transaction may include a nonzero gas refund. Must add it in now
                # It gets a refund if send has data and is not create. ie. there was a computation on receive

                if computation.msg.data != b'' and not computation.msg.is_create:
                    gas_refund_amount = computation.get_gas_remaining_including_refunds()

                    if gas_refund_amount > 0:
                        self.logger.debug("SAVING RECEIVABLE REFUND TX WITH HASH {} ON CHAIN {}".format(
                            encode_hex(computation.transaction_context.receive_tx_hash),
                            encode_hex(computation.transaction_context.refund_address)))


                        self.state.account_db.add_receivable_transaction(computation.transaction_context.refund_address,
                                                                         computation.transaction_context.receive_tx_hash,
                                                                         block_header_hash,
                                                                         refund_amount=gas_refund_amount)




    def apply_receipt_to_header(self, base_header: BaseBlockHeader, receipt: Receipt) -> BaseBlockHeader:
        new_header = base_header.copy(
            bloom=int(BloomFilter(base_header.bloom) | receipt.bloom),
            gas_used=base_header.gas_used + receipt.gas_used,
        )
        return new_header


    def contains_computation_calls(self, send_transactions: List[PhotonTransaction]) -> bool:
        # Caution: this function assumes computation calls are at the end of the list if they exist
        if len(send_transactions) == 0:
            return False
        else:
            return send_transactions[-1].created_by_computation


    def separate_normal_transactions_and_computation_calls(self, send_transactions: List[PhotonTransaction]) -> Tuple[List[PhotonTransaction], List[PhotonTransaction]]:
        normal_transactions = []
        computation_transactions = []
        computation_call_found = False
        for tx in send_transactions:
            if tx.created_by_computation:
                computation_transactions.append(tx)
                computation_call_found = True
            else:
                if computation_call_found:
                    raise ValidationError("Normal send transaction came after a computation call send transaction. This is not allowed.")
                normal_transactions.append(tx)

        return normal_transactions, computation_transactions

    def get_next_nonce_after_normal_transactions(self, send_transactions: List[PhotonTransaction]) -> int:
        if len(send_transactions) == 0:
            raise ValueError("Cannot get next nonce after normal transactions because the transaction list is empty.")

        if not self.contains_computation_calls(send_transactions):
            return send_transactions[-1].nonce + 1
        else:
            normal_transactions, computation_calls = self.separate_normal_transactions_and_computation_calls(send_transactions)
            if len(normal_transactions) > 0:
                return normal_transactions[-1].nonce + 1
            else:
                return computation_calls[0].nonce

    def get_nonce_for_computation_calls(self, block: PhotonBlock) -> int:
        if len(block.transactions) == 0:
            nonce = self.state.account_db.get_nonce(block.header.chain_address)
        else:
            nonce = self.get_next_nonce_after_normal_transactions(block.transactions)
        return nonce

    def add_computation_call_nonce_to_execution_context(self, block):
        nonce = self.get_nonce_for_computation_calls(block)
        self.state.execution_context.computation_call_nonce = nonce


    #
    # Validation
    #
    
    def validate_computation_call_send_transactions_against_block(self, block: PhotonBlock, computation_call_send_transactions: List[PhotonTransaction]) -> None:
        '''
        This function ensures that the computation call send transactions in the given block are the same as the ones the local
        VM produced. All parameters of the transactions should be the same except for the signature.
        :param block:
        :param computation_call_send_transactions:
        :return:
        '''
        self.logger.debug("Validating computation call send transactions in block vs the ones our VM generated.")
        send_transactions = block.transactions
        # This function also ensures that the transactions are in the correct order with computations after normal
        _, block_computation_call_send_transactions = self.separate_normal_transactions_and_computation_calls(send_transactions)

        if len(block_computation_call_send_transactions) != len(computation_call_send_transactions):
            raise ValidationError("The number of computation call send transactions in the block differ from the number of ones the local VM generated."
                                  "Number in block: {}, number generated here: {}".format(len(block_computation_call_send_transactions), len(computation_call_send_transactions)))

        for i in range(len(block_computation_call_send_transactions)):
            ensure_computation_call_send_transactions_are_equal(block_computation_call_send_transactions[i], computation_call_send_transactions[i])

    def validate_create_call(self,
                             call_message: Message,
                             current_nonce_for_computation_calls: int
                             ) -> None:
        if call_message.nonce != current_nonce_for_computation_calls:
            raise ValidationError(
                "A computation call or create was generated with a nonce that is different from what it should be. "
                "The nonce used to generate the call: {} | what it should be: {}".format(
                    call_message.nonce, current_nonce_for_computation_calls
                ))


