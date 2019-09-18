from hvm.vm.forks.boson.transaction_context import BosonTransactionContext

import itertools

from hvm.validation import (
    validate_canonical_address,
    validate_uint256,
    validate_word,
    validate_is_boolean,
)

from eth_typing import Address, Hash32

class PhotonTransactionContext(BosonTransactionContext):
    """
    This immutable object houses information that remains constant for the entire context of the VM
    execution.
    this_chain_address is the address of the chain that the currently executing transaction lives on.
    tx_caller is the address of the chain that sent the send transaction.
    """
    __slots__ = ['_gas_price',
                 '_is_receive',
                 '_origin',
                 '_send_tx_hash',
                 '_log_counter',
                 '_this_chain_address',
                 '_is_refund',
                 '_receive_tx_hash',
                 '_tx_caller',
                 '_tx_origin',
                 '_tx_code_address',
                 '_tx_signer',
                 ]

    def __init__(self, origin: Address, send_tx_hash: Hash32, this_chain_address: Address, gas_price: int = None,
                 receive_tx_hash: Hash32 = None, is_receive: bool = False, is_refund: bool = False, tx_caller: Address =None,
                 tx_origin: Address = None, tx_code_address: Address = None, tx_signer: Address = None):


        if tx_caller is not None:
            validate_canonical_address(tx_caller, title="TransactionContext.tx_caller")
        self._tx_caller = tx_caller

        if tx_origin is not None:
            validate_canonical_address(tx_origin, title="TransactionContext.tx_origin")
        self._tx_origin = tx_origin

        if tx_code_address is not None:
            validate_canonical_address(tx_code_address, title="TransactionContext.tx_code_address")
        self._tx_code_address = tx_code_address

        if tx_signer is not None:
            validate_canonical_address(tx_signer, title="TransactionContext.tx_signer")
        self._tx_signer = tx_signer

        super(PhotonTransactionContext, self).__init__(origin, send_tx_hash, this_chain_address, gas_price, receive_tx_hash,
                                                 is_receive, is_refund)



    @property
    def tx_caller(self):
        return self._tx_caller

    @property
    def tx_origin(self):
        return self._tx_origin

    @property
    def tx_code_address(self):
        return self._tx_code_address

    @property
    def tx_signer(self):
        return self._tx_signer

    @property
    def refund_address(self):
        if self.tx_origin is not None:
            return self.tx_origin
        else:
            return self.tx_signer

    @property
    def is_computation_call_origin(self):
        return self.tx_origin is not None or self.tx_caller is not None

    @property
    def is_surrogate_call(self):
        return self.tx_code_address is not None




