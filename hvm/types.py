from typing import NewType, Union

Timestamp = NewType('Timestamp', int)

BytesOrView = Union[bytes, memoryview]