import itertools

from hvm.validation import (
    validate_canonical_address,
    validate_uint256,
    validate_word,
    validate_is_boolean,
)

from eth_typing import Address, Hash32


class BaseTransactionContext:
    """
    This immutable object houses information that remains constant for the entire context of the VM
    execution.
    """
    __slots__ = ['_gas_price', '_is_receive', '_origin', '_send_tx_hash', '_log_counter', '_caller_chain_address', '_is_refund', '_receive_tx_hash']

    def __init__(self, origin: Address, send_tx_hash: Hash32, caller_chain_address:Address, gas_price: int = None, receive_tx_hash: Hash32 = None, is_receive: bool = False, is_refund: bool = False):
        if gas_price is not None:
            validate_uint256(gas_price, title="TransactionContext.gas_price")
        self._gas_price = gas_price
        validate_canonical_address(origin, title="TransactionContext.origin")
        self._origin = origin
        validate_canonical_address(caller_chain_address, title='caller_chain_address')
        self._caller_chain_address = caller_chain_address
        validate_is_boolean(is_receive, title="is_receive")
        self._is_receive = is_receive
        validate_is_boolean(is_refund, title="is_from_refund")
        self._is_refund = is_refund
        validate_word(send_tx_hash, title="send_tx_hash")
        self._send_tx_hash = send_tx_hash
        if receive_tx_hash is not None:
            validate_word(receive_tx_hash, title="receive_tx_hash")
        self._receive_tx_hash = receive_tx_hash

        self._log_counter = itertools.count()

    def get_next_log_counter(self):
        return next(self._log_counter)

    @property
    def gas_price(self):
        return self._gas_price

    @property
    def origin(self):
        return self._origin
    
    @property
    def is_receive(self):
        return self._is_receive

    @property
    def is_refund(self):
        return self._is_refund
    
    @property
    def send_tx_hash(self):
        return self._send_tx_hash

    @property
    def receive_tx_hash(self):
        return self._receive_tx_hash

    @property
    def caller_chain_address(self):
        return self._caller_chain_address

    
