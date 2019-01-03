from rlp_cython import sedes
from hvm.rlp.sedes import address

class HashOrNumber:

    def serialize(self, obj: int) -> bytes:
        if isinstance(obj, int):
            return sedes.big_endian_int.serialize(obj)
        return sedes.binary.serialize(obj)

    def deserialize(self, serial: bytes) -> int:
        if len(serial) == 32:
            return sedes.binary.deserialize(serial)
        return sedes.big_endian_int.deserialize(serial)



class AddressOrNone:

    def serialize(self, obj):
        if obj == None:
            return ''
        return address.serialize(obj)

    def deserialize(self, serial):
        if serial is None or serial == '':
            return None
        return address.deserialize(serial)


class HashOrNone:

    def serialize(self, obj):
        if obj == None:
            return ''
        return sedes.binary.serialize(obj)

    def deserialize(self, serial):
        if serial is None or serial == '':
            return None
        return sedes.binary.deserialize(serial)