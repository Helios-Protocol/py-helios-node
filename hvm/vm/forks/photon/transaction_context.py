from hvm.constants import CREATE_CONTRACT_ADDRESS
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
    __slots__ = ['_send_tx_to',
                 '_gas_price',
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
                 '_tx_create_address',
                 '_tx_signer',
                 '_tx_execute_on_send',
                 '_has_data'
                 ]

    def __init__(self, send_tx_to: Address,  origin: Address, send_tx_hash: Hash32, this_chain_address: Address, gas_price: int = None,
                 receive_tx_hash: Hash32 = None, is_receive: bool = False, is_refund: bool = False, tx_caller: Address =None,
                 tx_origin: Address = None, tx_code_address: Address = None, tx_create_address: Address = None, tx_signer: Address = None,
                 tx_execute_on_send = False, has_data: bool= False
                 ):

        if send_tx_to:
            validate_canonical_address(send_tx_to, title="TransactionContext.send_tx_to")
        self._send_tx_to = send_tx_to

        if tx_caller is not None:
            validate_canonical_address(tx_caller, title="TransactionContext.tx_caller")
        self._tx_caller = tx_caller

        if tx_create_address is not None:
            validate_canonical_address(tx_create_address, title="TransactionContext.tx_create_address")
        self._tx_create_address = tx_create_address

        if tx_origin is not None:
            validate_canonical_address(tx_origin, title="TransactionContext.tx_origin")
        self._tx_origin = tx_origin

        if tx_code_address is not None:
            validate_canonical_address(tx_code_address, title="TransactionContext.tx_code_address")
        self._tx_code_address = tx_code_address

        if tx_signer is not None:
            validate_canonical_address(tx_signer, title="TransactionContext.tx_signer")
        self._tx_signer = tx_signer

        validate_is_boolean(tx_execute_on_send, title="TransactionContext.tx_execute_on_send")
        self._tx_execute_on_send = tx_execute_on_send

        validate_is_boolean(has_data, title="TransactionContext.has_data")
        self._has_data = has_data

        super(PhotonTransactionContext, self).__init__(origin, send_tx_hash, this_chain_address, gas_price, receive_tx_hash,
                                                 is_receive, is_refund)

    @property
    def send_tx_to(self):
        return self._send_tx_to

    @property
    def tx_caller(self):
        return self._tx_caller

    @property
    def has_data(self):
        return self._has_data

    @property
    def tx_origin(self):
        return self._tx_origin

    @property
    def tx_code_address(self):
        return self._tx_code_address

    @property
    def tx_create_address(self):
        return self._tx_create_address

    @property
    def tx_signer(self):
        return self._tx_signer

    @property
    def tx_execute_on_send(self):
        return self._tx_execute_on_send

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

    @property
    def is_create_tx(self):
        return self.send_tx_to == CREATE_CONTRACT_ADDRESS or self.tx_create_address is not None

    @property
    def smart_contract_storage_address(self):
        if self.is_surrogate_call:
            return self.tx_code_address
        else:
            if self.send_tx_to:
                return self.send_tx_to
            else:
                raise ValueError("Transaction context doesn't know the storage address because it is create")


    #
    # Properties for any child transactions created by this transaction
    #

    @property
    def child_tx_origin(self):
        if self.is_computation_call_origin:
            origin = self.tx_origin
        else:
            # Needs to be the original sender so we know where to send the refund at the end.
            origin = self.refund_address

        return origin




