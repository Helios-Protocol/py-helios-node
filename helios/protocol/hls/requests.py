from typing import (
    Any,
    Dict,
    Tuple,
    Optional,
    List,
)

from eth_typing import (
    BlockIdentifier,
    Hash32,
    BlockNumber,
    Address,
)
from hp2p.protocol import BaseRequest

from helios.protocol.hls.constants import MAX_HEADERS_FETCH
from helios.protocol.common.requests import (
    BaseHeaderRequest,
)

from .commands import (
    BlockBodies,
    BlockHeaders,
    GetBlockBodies,
    GetBlockHeaders,
    GetNodeData,
    GetReceipts,
    NodeData,
    Receipts,
    GetBlocks,
    Blocks,
    GetNodeStakingScore,
    SendNodeStakingScore,
    GetHashFragments, SendHashFragments, GetChains, Chains, GetChainSegment)

from hvm.types import Timestamp

class HeaderRequest(BaseHeaderRequest):
    """
    TODO: this should be removed from this module.  It exists to allow
    `hp2p.handlers.PeerRequestHandler` to have a common API between light and
    full chains so maybe it should go there
    """
    max_size = MAX_HEADERS_FETCH

    def __init__(self,
                 block_number_or_hash: BlockIdentifier,
                 max_headers: int,
                 skip: int,
                 reverse: bool) -> None:
        self.block_number_or_hash = block_number_or_hash
        self.max_headers = max_headers
        self.skip = skip
        self.reverse = reverse


class GetBlockHeadersRequest(BaseRequest[Dict[str, Any]]):
    cmd_type = GetBlockHeaders
    response_type = BlockHeaders

    def __init__(self,
                 block_number_or_hash: BlockIdentifier,
                 max_headers: int,
                 skip: int,
                 reverse: bool) -> None:
        self.command_payload = {
            'block_number_or_hash': block_number_or_hash,
            'max_headers': max_headers,
            'skip': skip,
            'reverse': reverse
        }


class GetReceiptsRequest(BaseRequest[Tuple[Hash32, ...]]):
    cmd_type = GetReceipts
    response_type = Receipts

    def __init__(self, block_hashes: Tuple[Hash32, ...]) -> None:
        self.command_payload = block_hashes


class GetNodeDataRequest(BaseRequest[Tuple[Hash32, ...]]):
    cmd_type = GetNodeData
    response_type = NodeData

    def __init__(self, node_hashes: Tuple[Hash32, ...]) -> None:
        self.command_payload = node_hashes


class GetBlockBodiesRequest(BaseRequest[Tuple[Hash32, ...]]):
    cmd_type = GetBlockBodies
    response_type = BlockBodies

    def __init__(self, block_hashes: Tuple[Hash32, ...]) -> None:
        self.command_payload = block_hashes


class GetBlocksRequest(BaseRequest[Tuple[Hash32, ...]]):
    cmd_type = GetBlocks
    response_type = Blocks

    def __init__(self, block_hashes: Tuple[Hash32, ...]) -> None:
        self.command_payload = block_hashes

class GetChainSegmentRequest(BaseRequest[Dict[str, Any]]):
    cmd_type = GetChainSegment
    response_type = Blocks

    def __init__(self, chain_address: Address, block_number_start: int, block_number_end: int) -> None:
        self.command_payload = {'chain_address': chain_address,
                                'block_number_start': block_number_start,
                                'block_number_end': block_number_end}


class GetChainsRequest(BaseRequest[Tuple[Hash32, ...]]):
    cmd_type = GetChains
    response_type = Chains

    def __init__(self, timestamp: Timestamp, idx_list: List[int]) -> None:
        self.command_payload = {'timestamp': timestamp,
                                'idx_list': idx_list}

class GetNodeStakingScoreRequest(BaseRequest[BlockNumber]):
    cmd_type = GetNodeStakingScore
    response_type = SendNodeStakingScore

    def __init__(self, since_block: BlockNumber) -> None:
        self.command_payload = {'since_block': since_block}

class GetHashFragmentsRequest(BaseRequest[Dict[str, Any]]):
    cmd_type = GetHashFragments
    response_type = SendHashFragments

    def __init__(self, timestamp: Timestamp, fragment_length: int, only_these_indices: Optional[List[int]] = None, hash_type_id: int = 1) -> None:
        if only_these_indices is None:
            entire_window = True
            only_these_indices = []
        else:
            entire_window = False

        self.command_payload = {'timestamp': timestamp,
                                'fragment_length': fragment_length,
                                'entire_window': entire_window,
                                'only_these_indices': only_these_indices,
                                'hash_type_id': hash_type_id}
