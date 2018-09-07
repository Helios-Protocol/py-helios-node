"""
Module for sedes objects that use lists as serialization format.
"""
from collections import Sequence

from eth_utils import (
    to_list,
    to_tuple,
)

from rlp.exceptions import (
    SerializationError,
    ListSerializationError,
    DeserializationError,
    ListDeserializationError,
)

from rlp.sedes.binary import (
    Binary as BinaryClass,
)


def is_sedes(obj):
    """Check if `obj` is a sedes object.

    A sedes object is characterized by having the methods `serialize(obj)` and
    `deserialize(serial)`.
    """
    return hasattr(obj, 'serialize') and hasattr(obj, 'deserialize')


def is_sequence(obj):
    """Check if `obj` is a sequence, but not a string or bytes."""
    return isinstance(obj, Sequence) and not (
        isinstance(obj, str) or BinaryClass.is_valid_type(obj))


class List(list):

    """A sedes for lists, implemented as a list of other sedes objects.

    :param strict: If true (de)serializing lists that have a length not
                   matching the sedes length will result in an error. If false
                   (de)serialization will stop as soon as either one of the
                   lists runs out of elements.
    """

    def __init__(self, elements=None, strict=True):
        super(List, self).__init__()
        self.strict = strict

        if elements:
            for e in elements:
                if is_sedes(e):
                    self.append(e)
                elif isinstance(e, Sequence):
                    self.append(List(e))
                else:
                    raise TypeError(
                        'Instances of List must only contain sedes objects or '
                        'nested sequences thereof.'
                    )

    @to_list
    def serialize(self, obj):
        if not is_sequence(obj):
            raise ListSerializationError('Can only serialize sequences', obj)
        if self.strict:
            if len(self) != len(obj) or len(self) < len(obj):
                raise ListSerializationError('List has wrong length', obj)

        for index, (element, sedes) in enumerate(zip(obj, self)):
            try:
                yield sedes.serialize(element)
            except SerializationError as e:
                raise ListSerializationError(obj=obj, element_exception=e, index=index)

    @to_tuple
    def deserialize(self, serial):
        if not is_sequence(serial):
            raise ListDeserializationError('Can only deserialize sequences', serial)

        if self.strict and len(serial) != len(self):
            raise ListDeserializationError('List has wrong length', serial)

        for idx, (sedes, element) in enumerate(zip(self, serial)):
            try:
                yield sedes.deserialize(element)
            except DeserializationError as e:
                raise ListDeserializationError(serial=serial, element_exception=e, index=idx)


class CountableList(object):

    """A sedes for lists of arbitrary length.

    :param element_sedes: when (de-)serializing a list, this sedes will be
                          applied to all of its elements
    :param max_length: maximum number of allowed elements, or `None` for no limit
    """

    def __init__(self, element_sedes, max_length=None):
        self.element_sedes = element_sedes
        self.max_length = max_length

    @to_list
    def serialize(self, obj):
        if not is_sequence(obj):
            raise ListSerializationError('Can only serialize sequences', obj)

        if self.max_length is not None and len(obj) > self.max_length:
            raise ListSerializationError(
                'Too many elements ({}, allowed {})'.format(
                    len(obj),
                    self.max_length,
                ),
                obj=obj,
            )

        for index, element in enumerate(obj):
            try:
                yield self.element_sedes.serialize(element)
            except SerializationError as e:
                raise ListSerializationError(obj=obj, element_exception=e, index=index)

    @to_tuple
    def deserialize(self, serial):
        if not is_sequence(serial):
            raise ListDeserializationError('Can only deserialize sequences', serial=serial)
        for index, element in enumerate(serial):
            if self.max_length is not None and index >= self.max_length:
                raise ListDeserializationError(
                    'Too many elements (more than {})'.format(self.max_length),
                    serial=serial,
                )

            try:
                yield self.element_sedes.deserialize(element)
            except DeserializationError as e:
                raise ListDeserializationError(serial=serial, element_exception=e, index=index)



from rlp.exceptions import DeserializationError, SerializationError

cpdef bytes int_to_big_endian(int value):
    return value.to_bytes((value.bit_length() + 7) // 8 or 1, 'big')

cpdef int big_endian_to_int(bytes value):
    return int.from_bytes(value, 'big')

class BigEndianInt(object):
    """A sedes for big endian integers.

    :param l: the size of the serialized representation in bytes or `None` to
              use the shortest possible one
    """

    def __init__(self, l=None):
        self.l = l

    def serialize(self, obj):
        if isinstance(obj, bool) or not isinstance(obj, int):
            raise SerializationError('Can only serialize integers', obj)
        if self.l is not None and obj >= 256**self.l:
            raise SerializationError('Integer too large (does not fit in {} '
                                     'bytes)'.format(self.l), obj)
        if obj < 0:
            raise SerializationError('Cannot serialize negative integers', obj)

        if obj == 0:
            s = b''
        else:
            s = int_to_big_endian(obj)

        if self.l is not None:
            return b'\x00' * max(0, self.l - len(s)) + s
        else:
            return s

    def deserialize(self, serial):
        if self.l is not None and len(serial) != self.l:
            raise DeserializationError('Invalid serialization (wrong size)',
                                       serial)
        if self.l is None and len(serial) > 0 and serial[0:1] == b'\x00':
            raise DeserializationError('Invalid serialization (not minimal '
                                       'length)', serial)

        serial = serial or b'\x00'
        return big_endian_to_int(serial)


big_endian_int = BigEndianInt()
