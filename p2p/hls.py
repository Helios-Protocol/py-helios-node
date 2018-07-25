import logging
#import secrets
from typing import List, Union

from rlp import sedes

from evm.rlp.sedes import (
    address,
    hash32,
)
from evm.rlp.headers import BlockHeader
from evm.rlp.receipts import Receipt

from p2p.protocol import (
    Command,
    Protocol,
)
from p2p.rlp import (
    BlockBody, 
    P2PSendTransaction,
    P2PReceiveTransaction,
    BlockNumberKey,
    BlockHashKey,
    TimestampRootHashKey,
    P2PBlock
)
from p2p.sedes import (
    HashOrNumber,
    AddressOrNone,
    HashOrNone,
)


# Max number of items we can ask for in HLS requests. These are the values used in geth and if we
# ask for more than this the peers will disconnect from us.
MAX_STATE_FETCH = 384
MAX_BODIES_FETCH = 128
MAX_RECEIPTS_FETCH = 256
MAX_HEADERS_FETCH = 192


class Status(Command):
    _cmd_id = 0
    structure = [
        ('protocol_version', sedes.big_endian_int),
        ('network_id', sedes.big_endian_int),
        ('node_type', sedes.big_endian_int),
        ('chain_head_root_hashes', sedes.CountableList(sedes.List([sedes.big_endian_int, sedes.binary]))),
        ('salt', sedes.binary),
    ]


class NewBlockHashes(Command):
    _cmd_id = 1
    structure = sedes.CountableList(sedes.List([sedes.binary, sedes.big_endian_int]))


#TODO. fix
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
        ('block', sedes.List([BlockHeader,
                              sedes.CountableList(P2PSendTransaction),
                              sedes.CountableList(P2PReceiveTransaction)]))
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
#if none, then send trie root hash
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
    #this way is actually almost twice as fast as using a key... structure is [timestamp, root_hash]
    structure = sedes.CountableList(sedes.List([sedes.big_endian_int, sedes.binary]))
    #these are the same thing. Its just cleaner to work with an object. If we need to be able to iterate over the list then we can go back to list format
    #structure = sedes.CountableList(TimestampRootHashKey)
    
class GetUnorderedBlockHeaderHash(Command):
    _cmd_id = 21
    structure = sedes.CountableList(BlockNumberKey)

class UnorderedBlockHeaderHash(Command):
    _cmd_id = 22
    structure = sedes.CountableList(BlockHashKey)
   
#send the primary salt
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
    
class GetChainsSyncing(Command):
    _cmd_id = 27
    structure = [
        ('head_root_hash', hash32),
        ('head_hash_of_last_chain', hash32),
        ('window_start', sedes.big_endian_int),
        ('window_length', sedes.big_endian_int),
    ]
    
class Chain(Command):
    _cmd_id = 28
    structure = [
        ('is_last', sedes.boolean),
        ('blocks', sedes.CountableList(P2PBlock))]
    
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


class HLSProtocol(Protocol):
    name = 'HLS'
    version = 1
    _commands = [
        Status, NewBlockHashes, Transactions, GetBlockHeaders, BlockHeaders,
        GetBlockBodies, BlockBodies, NewBlock, NewBlock, NewBlock, 
        NewBlock, NewBlock, NewBlock, GetNodeData, NodeData,
        GetReceipts, Receipts, GetChainHeadTrieBranch, ChainHeadTrieBranch, GetChainHeadRootHashTimestamps,
        ChainHeadRootHashTimestamps, GetUnorderedBlockHeaderHash, UnorderedBlockHeaderHash, GetWalletAddressVerification, WalletAddressVerification,
        GetStakeForAddresses, StakeForAddresses, GetChainsSyncing, Chain, GetChronologicalBlockWindow, ChronologicalBlockWindow]
    cmd_length = 40
    logger = logging.getLogger("p2p.hls.HLSProtocol")

    def send_handshake(self, chain_info, salt):
        if chain_info.chain_head_root_hashes is None:
            chain_head_root_hashes = []
        else:
            chain_head_root_hashes = chain_info.chain_head_root_hashes
        
        #create salt for them to sign and send back
        resp = {
            'protocol_version': self.version,
            'network_id': self.peer.network_id,
            'node_type': chain_info.node_type,
            'chain_head_root_hashes': chain_head_root_hashes,
            'salt': salt,
        }
        #self.logger.debug("sending handshake with {}{}{}{}".format(self.version, self.peer.network_id, chain_info.node_type, chain_info.node_wallet_address))
        cmd = Status(self.cmd_id_offset)
        self.logger.debug("Sending HLS/Status msg: %s", resp)
        self.send(*cmd.encode(resp))

    def send_get_node_data(self, node_hashes: List[bytes]) -> None:
        cmd = GetNodeData(self.cmd_id_offset)
        header, body = cmd.encode(node_hashes)
        self.send(header, body)

    def send_node_data(self, nodes: List[bytes]) -> None:
        cmd = NodeData(self.cmd_id_offset)
        header, body = cmd.encode(nodes)
        self.send(header, body)

    def send_get_block_headers(self, block_number_or_hash: Union[int, bytes], 
                               max_headers: int, reverse: bool = True, wallet_address = None
                               ) -> None:
        """Send a GetBlockHeaders msg to the remote.

        This requests that the remote send us up to max_headers, starting from
        block_number_or_hash if reverse is False or ending at block_number_or_hash if reverse is
        True.
        """
        if max_headers > MAX_HEADERS_FETCH:
            raise ValueError(
                "Cannot ask for more than {} block headers in a single request".format(
                    MAX_HEADERS_FETCH))
        cmd = GetBlockHeaders(self.cmd_id_offset)
        # Number of block headers to skip between each item (i.e. step in python APIs).
        skip = 0
        data = {
            'block_number_or_hash': block_number_or_hash,
            'wallet_address': wallet_address,
            'max_headers': max_headers,
            'skip': skip,
            'reverse': reverse}
        header, body = cmd.encode(data)
        self.send(header, body)

    def send_block_headers(self, headers: List[BlockHeader]) -> None:
        cmd = BlockHeaders(self.cmd_id_offset)
        header, body = cmd.encode(headers)
        self.send(header, body)

    def send_get_block_bodies(self, block_hashes: List[bytes]) -> None:
        cmd = GetBlockBodies(self.cmd_id_offset)
        header, body = cmd.encode(block_hashes)
        self.send(header, body)

    def send_block_bodies(self, blocks: List[BlockBody]) -> None:
        cmd = BlockBodies(self.cmd_id_offset)
        header, body = cmd.encode(blocks)
        self.send(header, body)

    def send_get_receipts(self, block_hashes: List[bytes]) -> None:
        cmd = GetReceipts(self.cmd_id_offset)
        header, body = cmd.encode(block_hashes)
        self.send(header, body)

    def send_receipts(self, receipts: List[Receipt]) -> None:
        cmd = Receipts(self.cmd_id_offset)
        header, body = cmd.encode(receipts)
        self.send(header, body)
        
    def send_get_chain_head_trie_branch(self, node_hash = None) -> None:
        cmd = GetChainHeadTrieBranch(self.cmd_id_offset)
        header, body = cmd.encode(node_hash)
        self.send(header, body)
        
    def send_chain_head_trie_branch(self, node_hashes: List[bytes]) -> None:
        cmd = ChainHeadTrieBranch(self.cmd_id_offset)
        header, body = cmd.encode(node_hashes)
        self.send(header, body)
              
    def send_get_chain_head_root_hash_timestamps(self, after_timestamp) -> None:
        cmd = GetChainHeadRootHashTimestamps(self.cmd_id_offset)
        data = {'after_timestamp': after_timestamp}
        header, body = cmd.encode(data)
        self.send(header, body)
        
    def send_chain_head_root_hash_timestamps(self, root_hash_timestamps) -> None:
        cmd = ChainHeadRootHashTimestamps(self.cmd_id_offset)
        header, body = cmd.encode(root_hash_timestamps)
        self.send(header, body)
        
    def send_get_unordered_block_header_hash(self, block_number_keys) -> None:
        cmd = GetUnorderedBlockHeaderHash(self.cmd_id_offset)
        header, body = cmd.encode(block_number_keys)
        self.send(header, body)
        
    def send_unordered_block_header_hash(self, block_hash_keys) -> None:
        cmd = UnorderedBlockHeaderHash(self.cmd_id_offset)
        header, body = cmd.encode(block_hash_keys)
        self.send(header, body)
        
    def send_get_wallet_address_verification(self, salt) -> None:
        cmd = GetWalletAddressVerification(self.cmd_id_offset)
        data = {
            'salt': salt}
        header, body = cmd.encode(data)
        self.send(header, body)
        
    def send_wallet_address_verification(self, salt, v, r, s) -> None:
        data = {
            'salt': salt,
            'v': v,
            'r': r,
            's': s}
        cmd = WalletAddressVerification(self.cmd_id_offset)
        header, body = cmd.encode(data)
        self.send(header, body)
        

    def send_get_stake_for_addresses(self, addresses) -> None:
        cmd = GetStakeForAddresses(self.cmd_id_offset)
        data = {
            'addresses': addresses}
        header, body = cmd.encode(data)
        self.send(header, body)
        
    def send_stake_for_addresses(self, address_stake_list) -> None:
        data = {
            'stakes': address_stake_list
            }
        cmd = StakeForAddresses(self.cmd_id_offset)
        header, body = cmd.encode(data)
        self.send(header, body)
        
    def send_get_chains_syncing(self, chain_request_info) -> None:
        cmd = GetChainsSyncing(self.cmd_id_offset)
        data = {
            'head_root_hash': chain_request_info.head_root_hash,
            'head_hash_of_last_chain': chain_request_info.head_hash_of_last_chain,
            'window_start': chain_request_info.window_start,
            'window_length': chain_request_info.window_length}
        header, body = cmd.encode(data)
        self.send(header, body)
    
    def send_chain(self, list_of_blocks, is_last) -> None:
        cmd = Chain(self.cmd_id_offset)
        data = {
            'is_last': is_last,
            'blocks': list_of_blocks}
        header, body = cmd.encode(data)
        self.send(header, body)
        
    def send_get_chronological_block_window(self, start_timestamp) -> None:
        cmd = GetChronologicalBlockWindow(self.cmd_id_offset)
        data = {
            'start_timestamp': start_timestamp}
        header, body = cmd.encode(data)
        self.send(header, body)
        
    def send_chronological_block_window(self, list_of_blocks, final_root_hash) -> None:
        cmd = ChronologicalBlockWindow(self.cmd_id_offset)
        data = {
            'blocks': list_of_blocks,
            'final_root_hash': final_root_hash}
        header, body = cmd.encode(data)
        self.send(header, body)
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        