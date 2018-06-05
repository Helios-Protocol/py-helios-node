import itertools

from evm.validation import (
    validate_canonical_address,
    validate_uint256,
    validate_word,
    validate_is_boolean,
)


class BaseTransactionContext:
    """
    This immutable object houses information that remains constant for the entire context of the VM
    execution.
    """
    __slots__ = ['_gas_price', '_origin', '_log_counter']

    def __init__(self, origin, send_tx_hash, gas_price = None, is_receive = False):
        if gas_price is not None:
            validate_uint256(gas_price, title="TransactionContext.gas_price")
        self._gas_price = gas_price
        validate_canonical_address(origin, title="TransactionContext.origin")
        self._origin = origin
        validate_is_boolean(is_receive, title="is_receive")
        self._is_receive = is_receive
        validate_word(send_tx_hash, title="Send tx hash")
        self._send_tx_hash = send_tx_hash

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
    def send_tx_hash(self):
        return self._send_tx_hash
    
