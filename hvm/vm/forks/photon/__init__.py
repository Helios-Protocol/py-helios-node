from hvm.vm.forks.photon.consensus import PhotonConsensusDB
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

from hvm.rlp.headers import BaseBlockHeader

from hvm.vm.forks.boson import make_boson_receipt

from typing import Tuple, List

from eth_bloom import (
    BloomFilter,
)
from .utils import get_computation_gas_refund_amount

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


    def apply_all_transactions(self, block: PhotonBlock) -> Tuple[BaseBlockHeader, List[Receipt], List[PhotonComputation], List[PhotonComputation], List[PhotonTransaction]]:
        # #run all of the transactions.
        # last_header, receipts, send_computations = self._apply_all_send_transactions(block.transactions, block.header)
        #
        #
        # #then run all receive transactions
        # last_header, receive_receipts, receive_computations, processed_receive_transactions = self._apply_all_receive_transactions(block.receive_transactions, last_header)

        # First, run all of the receive transactions
        last_header, receive_receipts, receive_computations, processed_receive_transactions = self._apply_all_receive_transactions(block.receive_transactions, block.header)

        for receive_computation in receive_computations:
            if receive_computation.msg.data != b'':
                # Only check if there is actually transaction data because this will be an expensive function
                external_call_messages = receive_computation.get_all_children_external_call_messages()

                if len(external_call_messages) > 0:
                    gas_remaining_for_children_txs = receive_computation.get_gas_remaining_including_refunds()
                    gas_for_each_tx = int(gas_remaining_for_children_txs/len(external_call_messages))

                    #Add this to the first tx
                    gas_remainder = gas_remaining_for_children_txs - gas_for_each_tx*len(external_call_messages)



        # TODO, go through receive computations looking for child call messages. Then calculate gas remaining using:
        # gas_remaining = computation.get_gas_remaining()
        # gas_refunded = computation.get_gas_refund()
        #
        # gas_used = send_transaction.gas - gas_remaining
        # gas_refund = min(gas_refunded, gas_used // 2)
        # gas_refund_amount = (gas_refund + gas_remaining) * send_transaction.gas_price
        #
        # self.vm_state.logger.debug(
        #     'SAVING REFUND TO RECEIVE TX: %s -> %s',
        #     gas_refund_amount,
        #     encode_hex(computation.msg.sender),
        # )
        # receive_transaction = receive_transaction.copy(remaining_refund=gas_refund_amount)
        # TODO: then split the remaining up evenly over child computations
        # TODO: then create the new transactions and add them to the block. But only add them if they don't already exist there.
        # Only add them to the block if it is a queueblock. Otherwise, just check to make sure all tx params are identical except
        # for the signature.
        # Need a check - send transactions can only originate from a computation. If there are more send transactions than
        # came out of these computations - it is an invalid block.
        #
        # When processing send transactions on a smart contract, subtract value like normal. But we have to make sure that the
        # transaction originated from code on this chain. NO - we dont process normally, because the signing sender wont be the one paying
        # It needs to subtract any value from this smart contract account instead.
        #
        # We also need to make sure the VM doesnt subtract any gas for these transactions. The gas has already been subtracted.
        #
        #
        # Who is going to sign these transactions? The sender needs to be the person who sent the first transaction so that they
        # can be correctly refunded. But they arent here to sign it... Add another field to the transaction for refund address?


        # Then, run all of the send transactions
        last_header, receipts, send_computations = self._apply_all_send_transactions(block.transactions, last_header)

        # Combine receipts in the send transaction, receive transaction order
        receipts.extend(receive_receipts)

        return last_header, receipts, receive_computations, send_computations, processed_receive_transactions


    def apply_receipt_to_header(self, base_header: BaseBlockHeader, receipt: Receipt) -> BaseBlockHeader:
        new_header = base_header.copy(
            bloom=int(BloomFilter(base_header.bloom) | receipt.bloom),
            gas_used=base_header.gas_used + receipt.gas_used,
        )
        return new_header


    min_time_between_blocks = constants.MIN_TIME_BETWEEN_BLOCKS