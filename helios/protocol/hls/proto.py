import logging
from typing import (
    List,
    Tuple,
    TYPE_CHECKING,
    Union,
)

from eth_typing import (
    Hash32,
    BlockNumber,
)

from hvm.rlp.headers import BlockHeader
from hvm.rlp.receipts import Receipt
from hvm.rlp.consensus import NodeStakingScore

from hp2p.protocol import (
    Protocol,
)

from hvm.constants import (
    UINT_256_MAX
)

from helios.protocol.common.peer import ChainInfo
from helios.rlp_templates.hls import (
    BlockBody,
    P2PBlock,
)

from hvm.types import Timestamp

from .commands import (
    BlockBodies,
    BlockHeaders,
    GetBlockBodies,
    GetBlockHeaders,
    GetNodeData,
    GetReceipts,
    NewBlock,
    NewBlockHashes,
    NodeData,
    Receipts,
    Status,
    Transactions,
    GetChainHeadTrieBranch,
    ChainHeadTrieBranch,
    GetChainHeadRootHashTimestamps,
    ChainHeadRootHashTimestamps,
    GetUnorderedBlockHeaderHash,
    UnorderedBlockHeaderHash,
    GetWalletAddressVerification,
    WalletAddressVerification,
    GetStakeForAddresses,
    StakeForAddresses,
    GetChains,
    GetChronologicalBlockWindow,
    ChronologicalBlockWindow,
    GetMinGasParameters,
    MinGasParameters,
    GetChainSegment,
    GetBlocks,
    Blocks,
    GetNodeStakingScore,
    SendNodeStakingScore,
    GetHashFragments,
    SendHashFragments,
    Chains)
from .constants import (
    MAX_HEADERS_FETCH,

)

if TYPE_CHECKING:
    from .peer import HLSPeer  # noqa: F401


class HLSProtocol(Protocol):
    name = 'HLS'
    version = 1
    _commands = [
        Status, NewBlockHashes, Transactions, GetBlockHeaders, BlockHeaders,
        GetBlockBodies, BlockBodies, NewBlock, NewBlock, NewBlock,
        NewBlock, NewBlock, NewBlock, GetNodeData, NodeData,
        GetReceipts, Receipts, GetChainHeadTrieBranch, ChainHeadTrieBranch, GetChainHeadRootHashTimestamps,
        ChainHeadRootHashTimestamps, GetUnorderedBlockHeaderHash, UnorderedBlockHeaderHash, GetWalletAddressVerification, WalletAddressVerification,
        GetStakeForAddresses, StakeForAddresses, GetChains, Chains, GetChronologicalBlockWindow,
        ChronologicalBlockWindow, GetMinGasParameters, MinGasParameters, GetChainSegment, GetBlocks,
        Blocks, GetNodeStakingScore, SendNodeStakingScore, GetHashFragments, SendHashFragments]
    cmd_length = 60
    logger = logging.getLogger("hp2p.hls.HLSProtocol")

    peer: 'HLSPeer'

    def send_handshake(self, chain_info: ChainInfo, salt):
        # create salt for them to sign and send back
        resp = {
            'protocol_version': self.version,
            'network_id': self.peer.network_id,
            'node_type': chain_info.node_type,
            'genesis_block_hash': chain_info.genesis_block_hash,
            'salt': salt,
        }
        # self.logger.debug("sending handshake with {}{}{}{}".format(self.version, self.peer.network_id, chain_info.node_type, chain_info.node_wallet_address))
        cmd = Status(self.cmd_id_offset)
        self.logger.debug("Sending HLS/Status msg: %s", resp)
        self.send(*cmd.encode(resp))

    #
    # Node Data
    #
    def send_get_node_data(self, node_hashes: List[bytes]) -> None:
        cmd = GetNodeData(self.cmd_id_offset)
        header, body = cmd.encode(node_hashes)
        self.send(header, body)

    def send_node_data(self, nodes: List[bytes]) -> None:
        cmd = NodeData(self.cmd_id_offset)
        header, body = cmd.encode(nodes)
        self.send(header, body)

    def send_get_block_headers(self, block_number_or_hash: Union[int, bytes],
                               max_headers: int, reverse: bool = True, wallet_address=None
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

    def send_get_chain_head_trie_branch(self, node_hash=None) -> None:
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

    def send_get_chain_segment(self, chain_address, block_number_start, block_number_end=None) -> None:
        cmd = GetChainSegment(self.cmd_id_offset)
        if block_number_end is None:
            block_number_end = 0

        data = {
            'chain_address': chain_address,
            'block_number_start': block_number_start,
            'block_number_end': block_number_end,
        }
        header, body = cmd.encode(data)
        self.send(header, body)

    def send_get_chains(self, timestamp: Timestamp, idx_list: List[int]) -> None:
        cmd = GetChains(self.cmd_id_offset)
        data = {
            'timestamp': timestamp,
            'idx_list': idx_list}
        header, body = cmd.encode(data)
        self.send(header, body)

    def send_chains(self, chains: List[List[P2PBlock]]) -> None:
        cmd = Chains(self.cmd_id_offset)
        data = {
            'chains': chains}
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

    def send_new_block(self, block: P2PBlock) -> None:
        cmd = NewBlock(self.cmd_id_offset)
        data = {
            'block': block}
        header, body = cmd.encode(data)
        self.send(header, body)

    def send_get_min_gas_parameters(self, num_centiseconds_from_now=50) -> None:
        cmd = GetMinGasParameters(self.cmd_id_offset)
        data = {
            'num_centiseconds_from_now': num_centiseconds_from_now}
        header, body = cmd.encode(data)
        self.send(header, body)

    def send_min_gas_parameters(self, hist_net_tpc_capability, hist_min_allowed_gas_price) -> None:
        cmd = MinGasParameters(self.cmd_id_offset)
        data = {
            'hist_net_tpc_capability': hist_net_tpc_capability,
            'hist_min_allowed_gas_price': hist_min_allowed_gas_price}
        header, body = cmd.encode(data)
        self.send(header, body)

    def send_blocks(self, list_of_blocks: List[P2PBlock]) -> None:
        cmd = Blocks(self.cmd_id_offset)
        data = list_of_blocks
        header, body = cmd.encode(data)
        self.send(header, body)

    def send_node_staking_score(self, node_staking_score: NodeStakingScore) -> None:
        cmd = SendNodeStakingScore(self.cmd_id_offset)
        data = {'node_staking_score': node_staking_score}
        header, body = cmd.encode(data)
        self.send(header, body)

    def send_hash_fragments(self,
                            fragments: List[bytes],
                            timestamp: Timestamp,
                            fragment_length: int,
                            hexary_trie_root_hash_of_complete_window: Hash32,
                            hash_type_id: int) -> None:
        cmd = SendHashFragments(self.cmd_id_offset)
        data = {'fragments': fragments,
                'timestamp': timestamp,
                'fragment_length': fragment_length,
                'root_hash_of_the_full_hashes': hexary_trie_root_hash_of_complete_window,
                'hash_type_id': hash_type_id}
        header, body = cmd.encode(data)
        self.send(header, body)

