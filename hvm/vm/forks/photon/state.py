from __future__ import absolute_import
from typing import Type  # noqa: F401

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

class PhotonTransactionExecutor(BosonTransactionExecutor):
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
            if computation.msg.data != b'' and not computation.msg.is_create:
                if computation.has_external_call_messages and not computation.is_error:
                    # If the computation has child transactions that it must make, and there were no errors, then save the gas to send them.
                    # But if there was an error, then we still return whatever gas is left over like normal, which is the else.
                    self.vm_state.logger.debug(
                        'SAVING REFUND FOR CHILD CALLS: tx_hash = {}'.format(receive_transaction.hash)
                    )
                else:

                    gas_refund_amount = computation.get_gas_remaining_including_refunds()

                    self.vm_state.logger.debug(
                        'SAVING REFUND TO RECEIVE TX: %s -> %s',
                        gas_refund_amount,
                        encode_hex(computation.msg.sender),
                    )
                    receive_transaction = receive_transaction.copy(remaining_refund=gas_refund_amount)

            return receive_transaction
        else:
            # this is a send transaction. Refunds are only possible on receive tx. So send it back unmodified
            return send_transaction


class PhotonState(BosonState):
    computation_class: Type[PhotonComputation] = PhotonComputation
    transaction_executor: Type[PhotonTransactionExecutor] = PhotonTransactionExecutor
    account_db_class: Type[PhotonAccountDB] = PhotonAccountDB
    transaction_context_class: Type[PhotonTransactionContext] = PhotonTransactionContext
    
