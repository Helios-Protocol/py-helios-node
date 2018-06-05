class ExecutionContext:
    _timestamp = None
    _number = None
    _gas_limit = None
    _prev_hashes = None

    def __init__(
            self,
            timestamp,
            block_number,
            gas_limit,
            prev_hashes):
        self._timestamp = timestamp
        self._block_number = block_number
        self._gas_limit = gas_limit
        self._prev_hashes = prev_hashes


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
    def prev_hashes(self):
        return self._prev_hashes
