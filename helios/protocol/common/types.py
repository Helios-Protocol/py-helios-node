from typing import (
    Dict,
    Tuple,
    TypeVar,
)

from hvm.rlp.receipts import Receipt
from eth_typing import (
    Hash32,
)
from hp2p.peer import BasePeer
from hp2p.protocol import PayloadType

from helios.rlp_templates.hls import BlockBody

TPeer = TypeVar('TPeer', bound=BasePeer)

# A payload delivered by a responding command
TResponsePayload = TypeVar('TResponsePayload', bound=PayloadType)

# The returned value at the end of an exchange
TResult = TypeVar('TResult')

# (
#   (node_hash, node),
#   ...
# )
NodeDataBundles = Tuple[Tuple[Hash32, bytes], ...]

# (receipts_in_block_a, receipts_in_block_b, ...)
ReceiptsByBlock = Tuple[Tuple[Receipt, ...], ...]

# (
#   (receipts_in_block_a, (receipts_root_hash, receipts_trie_nodes),
#   (receipts_in_block_b, (receipts_root_hash, receipts_trie_nodes),
#   ...
# (
ReceiptsBundles = Tuple[Tuple[Tuple[Receipt, ...], Tuple[Hash32, Dict[Hash32, bytes]]], ...]

# (BlockBody, (txn_root, txn_trie_data), uncles_hash)
BlockBodyBundles = Tuple[Tuple[
    BlockBody,
    Tuple[Hash32, Dict[Hash32, bytes]],
    Hash32,
], ...]
