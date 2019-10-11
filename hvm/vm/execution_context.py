from hvm.types import Timestamp
from hvm.validation import validate_uint256


class ExecutionContext:
    _timestamp: Timestamp = None
    _block_number: int = None
    _gas_limit: int = None
    _computation_call_nonce: int = None
    _network_id: int = None

    def __init__(
            self,
            timestamp,
            block_number,
            gas_limit,
            network_id: int,
            computation_call_nonce=None):
        self._timestamp = timestamp
        self._block_number = block_number
        self._gas_limit = gas_limit
        self._computation_call_nonce = computation_call_nonce

        validate_uint256(network_id)
        self._network_id = network_id


    @property
    def timestamp(self):
        return self._timestamp

    @property
    def block_number(self):
        return self._block_number

    @property
    def gas_limit(self):
        return self._gas_limit

    @property
    def computation_call_nonce(self):
        return self._computation_call_nonce

    @computation_call_nonce.setter
    def computation_call_nonce(self, val):
        self._computation_call_nonce = val

    def increment_computation_call_nonce(self):
        self._computation_call_nonce += 1

    @property
    def network_id(self):
        return self._network_id

