from hvm.vm.forks.boson import BosonComputation
from hvm.vm.forks.boson.computation import BOSON_PRECOMPILES
from hvm.vm.forks.photon.transaction_context import PhotonTransactionContext

from .opcodes import PHOTON_OPCODES

from hvm import constants

from hvm.utils.hexadecimal import (
    encode_hex,
)

from hvm.exceptions import (
    InsufficientFunds,
    StackDepthLimit,
)


PHOTON_PRECOMPILES = BOSON_PRECOMPILES

class PhotonComputation(BosonComputation):
    """
    A class for all execution computations in the ``Byzantium`` fork.
    Inherits from :class:`~hvm.vm.forks.spurious_dragon.computation.SpuriousDragonComputation`
    """
    # Override
    opcodes = PHOTON_OPCODES
    _precompiles = PHOTON_PRECOMPILES

    transaction_context: PhotonTransactionContext = None

    def apply_message(self, validate=True):
        snapshot = self.state.snapshot()

        if self.msg.depth > constants.STACK_DEPTH_LIMIT:
            raise StackDepthLimit("Stack depth limit reached")

        if self.msg.should_transfer_value:
            if self.transaction_context.is_refund:

                self.state.account_db.delta_balance(self.msg.sender, self.msg.refund_amount)
                self.logger.debug(
                    "REFUNDED: %s into %s",
                    self.msg.refund_amount,
                    encode_hex(self.msg.sender),
                )

            elif self.transaction_context.is_receive:

                if self.msg.value:
                    self.state.account_db.delta_balance(self.msg.storage_address, self.msg.value)
                    self.logger.debug(
                        "RECEIVED: %s into %s",
                        self.msg.value,
                        encode_hex(self.msg.storage_address),
                    )
            elif self.msg.value:
                # this is a send transaction
                if validate:
                    sender_balance = self.state.account_db.get_balance(self.msg.sender)

                    if sender_balance < self.msg.value:
                        raise InsufficientFunds(
                            "Insufficient funds: {0} < {1}".format(sender_balance, self.msg.value)
                        )

                self.state.account_db.delta_balance(self.msg.sender, -1 * self.msg.value)

                self.logger.debug(
                    "SENT: %s from %s to pending transactions",
                    self.msg.value,
                    encode_hex(self.msg.sender),
                )

        self.state.account_db.touch_account(self.msg.storage_address)

        if self.transaction_context.is_refund:
            # We never run computations on a refund
            self.state.commit(snapshot)
            computation = self

        elif self.transaction_context.is_receive:
            # this is when we run all computation normally
            computation = self.apply_computation(
                self.state,
                self.msg,
                self.transaction_context,
            )

            computation.set_error_if_not_enough_gas_for_external_calls()

            if computation.is_error:
                self.state.revert(snapshot)
            else:
                self.state.commit(snapshot)

        else:
            # this is a send transaction. We only run computation if is_create = True, and in that case we only run it to determine
            # the gas cost. So we create a snapshot to remove any changes other thank calculating gas cost.

            if self.msg.is_create:
                computation_snapshot = self.state.snapshot()

                computation = self.apply_computation(
                    self.state,
                    self.msg,
                    self.transaction_context,
                )

                if computation.is_error:
                    # This will revert the computation snapshot as well.
                    self.state.revert(snapshot)
                else:
                    # computation worked, but we don't want it yet until the receive transaction. So lets revert the computation
                    # but commit the transaction above.
                    if self.logger:
                        self.logger.debug(
                            "REVERTING COMPUTATION FOR CONTRACT DEPLOYMENT. WILL DEPLOY ON RECEIVE TX."
                        )
                    self.state.revert(computation_snapshot)
                    self.state.commit(snapshot)

            else:
                computation = self

        return computation