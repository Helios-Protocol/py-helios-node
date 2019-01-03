from typing import (
    cast,
    Tuple,
)

from rlp_cython import sedes

from hvm.rlp.headers import BlockHeader
from hvm.rlp.receipts import Receipt
from hvm.rlp.consensus import NodeStakingScore

from hvm.rlp.sedes import (
    address,
    hash32,
)

from hp2p.protocol import (
    Command,
    _DecodedMsgType,
)

from helios.protocol.common.commands import BaseBlockHeaders
from helios.rlp_templates.hls import BlockBody
from helios.rlp_templates.sedes import HashOrNumber

from helios.rlp_templates.hls import (
    BlockBody,
    P2PSendTransaction,
    P2PReceiveTransaction,
    BlockNumberKey,
    BlockHashKey,
    TimestampRootHashKey,
    P2PBlock
)
from helios.rlp_templates.sedes import (
    HashOrNumber,
    AddressOrNone,
    HashOrNone,
)

class Status(Command):
    _cmd_id = 0
    structure = [
        ('protocol_version', sedes.big_endian_int),
        ('network_id', sedes.big_endian_int),
        ('node_type', sedes.big_endian_int),
        ('genesis_block_hash', hash32),
        ('salt', sedes.binary),
    ]


class NewBlockHashes(Command):
    _cmd_id = 1
    structure = sedes.CountableList(sedes.List([sedes.binary, sedes.big_endian_int]))


# TODO. fix
class Transactions(Command):
    _cmd_id = 2
    structure = sedes.CountableList(P2PSendTransaction)


class GetBlockHeaders(Command):
    _cmd_id = 3
    structure = [
        ('block_number_or_hash', HashOrNumber()),
        ('wallet_address', AddressOrNone()),
        ('max_headers', sedes.big_endian_int),
        ('skip', sedes.big_endian_int),
        ('reverse', sedes.boolean),
    ]


class BlockHeaders(Command):
    _cmd_id = 4
    structure = sedes.CountableList(BlockHeader)


class GetBlockBodies(Command):
    _cmd_id = 5
    structure = sedes.CountableList(sedes.binary)


class BlockBodies(Command):
    _cmd_id = 6
    structure = sedes.CountableList(BlockBody)


class NewBlock(Command):
    _cmd_id = 7
    structure = [
        ('block', P2PBlock),
    ]


class GetNodeData(Command):
    _cmd_id = 13
    structure = sedes.CountableList(sedes.binary)


class NodeData(Command):
    _cmd_id = 14
    structure = sedes.CountableList(sedes.binary)


class GetReceipts(Command):
    _cmd_id = 15
    structure = sedes.CountableList(sedes.binary)


class Receipts(Command):
    _cmd_id = 16
    structure = sedes.CountableList(sedes.CountableList(Receipt))


'''
Consensus commands
'''


# if none, then send trie root hash
class GetChainHeadTrieBranch(Command):
    _cmd_id = 17
    structure = HashOrNone()


class ChainHeadTrieBranch(Command):
    _cmd_id = 18
    structure = sedes.CountableList(hash32)


class GetChainHeadRootHashTimestamps(Command):
    _cmd_id = 19
    structure = [('after_timestamp', sedes.big_endian_int)]


class ChainHeadRootHashTimestamps(Command):
    _cmd_id = 20
    # this way is actually almost twice as fast as using a key... structure is [timestamp, root_hash]
    structure = sedes.CountableList(sedes.List([sedes.big_endian_int, sedes.binary]))
    # these are the same thing. Its just cleaner to work with an object. If we need to be able to iterate over the list then we can go back to list format
    # structure = sedes.CountableList(TimestampRootHashKey)


class GetUnorderedBlockHeaderHash(Command):
    _cmd_id = 21
    structure = sedes.CountableList(BlockNumberKey)


class UnorderedBlockHeaderHash(Command):
    _cmd_id = 22
    structure = sedes.CountableList(BlockHashKey)


# send the primary salt
class GetWalletAddressVerification(Command):
    _cmd_id = 23
    structure = [
        ('salt', sedes.binary)
    ]


class WalletAddressVerification(Command):
    _cmd_id = 24
    structure = [
        ('salt', sedes.binary),
        ('v', sedes.big_endian_int),
        ('r', sedes.big_endian_int),
        ('s', sedes.big_endian_int),
    ]


class GetStakeForAddresses(Command):
    _cmd_id = 25
    structure = [
        ('addresses', sedes.CountableList(address))
    ]


class StakeForAddresses(Command):
    _cmd_id = 26
    structure = [
        ('stakes', sedes.CountableList(sedes.List([address, sedes.big_endian_int])))
    ]


class GetChains(Command):
    _cmd_id = 27
    structure = [
        ('timestamp', sedes.f_big_endian_int),
        ('idx_list', sedes.FCountableList(sedes.f_big_endian_int))
    ]


class Chains(Command):
    _cmd_id = 28
    structure = [
        ('chains', sedes.CountableList(sedes.CountableList(P2PBlock)))]


class GetChronologicalBlockWindow(Command):
    _cmd_id = 29
    structure = [
        ('start_timestamp', sedes.big_endian_int),
    ]


class ChronologicalBlockWindow(Command):
    _cmd_id = 30
    structure = [
        ('blocks', sedes.CountableList(P2PBlock)),
        ('final_root_hash', hash32)]


class GetMinGasParameters(Command):
    _cmd_id = 31
    structure = [
        ('num_centiseconds_from_now', sedes.big_endian_int),
    ]


class MinGasParameters(Command):
    _cmd_id = 32
    structure = [
        ('hist_net_tpc_capability', sedes.CountableList(sedes.List([sedes.big_endian_int, sedes.big_endian_int]))),
        ('hist_min_allowed_gas_price', sedes.CountableList(sedes.List([sedes.big_endian_int, sedes.big_endian_int])))]


class GetChainSegment(Command):
    _cmd_id = 33
    structure = [
        ('chain_address', address),
        ('block_number_start', sedes.big_endian_int),
        ('block_number_end', sedes.big_endian_int)
    ]

class GetBlocks(Command):
    _cmd_id = 34
    structure = sedes.CountableList(hash32)

class Blocks(Command):
    _cmd_id = 35
    structure = sedes.CountableList(P2PBlock)

class GetNodeStakingScore(Command):
    _cmd_id = 36
    structure = [
        ('since_block', sedes.f_big_endian_int)
    ]

class SendNodeStakingScore(Command):
    _cmd_id = 37
    structure = [
        ('node_staking_score', NodeStakingScore)
    ]


class GetHashFragments(Command):
    _cmd_id = 38
    structure = [
        ('timestamp', sedes.f_big_endian_int),
        ('fragment_length', sedes.f_big_endian_int),
        ('entire_window', sedes.boolean),
        ('only_these_indices', sedes.FCountableList(sedes.f_big_endian_int)),
        ('hash_type_id',sedes.f_big_endian_int),
    ]

class SendHashFragments(Command):
    _cmd_id = 39
    structure = [
        ('fragments', sedes.FCountableList(sedes.binary)),
        ('timestamp', sedes.f_big_endian_int),
        ('fragment_length', sedes.f_big_endian_int),
        ('root_hash_of_the_full_hashes', hash32),
        ('hash_type_id', sedes.f_big_endian_int),
    ]




