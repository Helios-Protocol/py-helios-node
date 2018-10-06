import rlp
from rlp import sedes

from hvm.rlp.sedes import (
    address,
    hash32,
    trie_root,
)

from hvm.rlp.headers import BlockHeader
from hvm.rlp.transactions import BaseTransaction


# This is needed because BaseTransaction has several @abstractmethods, which means it can't be
# instantiated.
class P2PTransaction(rlp.Serializable):
    fields = BaseTransaction._meta.fields


class P2PSendTransaction(rlp.Serializable):
    fields = BaseTransaction._meta.fields


# TODO. link this to the definition in the vm somehow.
class P2PReceiveTransaction(rlp.Serializable):
    fields = [
        ('sender_block_hash', hash32),
        ('send_transaction_hash', hash32),
    ]


class P2PBlock(rlp.Serializable):
    transaction_class = P2PSendTransaction
    receive_transaction_class = P2PReceiveTransaction
    fields = [
        ('header', BlockHeader),
        ('transactions', sedes.CountableList(P2PSendTransaction)),
        ('receive_transactions', sedes.CountableList(P2PReceiveTransaction))
    ]


class BlockBody(rlp.Serializable):
    fields = [
        ('send_transactions', sedes.CountableList(P2PSendTransaction)),
        ('receive_transactions', sedes.CountableList(P2PReceiveTransaction)),
    ]


class BlockNumberKey(rlp.Serializable):
    fields = [
        ('wallet_address', address),
        ('block_number', sedes.big_endian_int)
    ]


class BlockHashKey(rlp.Serializable):
    fields = [
        ('wallet_address', address),
        ('block_number', sedes.big_endian_int),
        ('block_hash', hash32)
    ]


class TimestampRootHashKey(rlp.Serializable):
    fields = [
        ('timestamp', sedes.big_endian_int),
        ('root_hash', trie_root),
    ]
