from typing import (
    Optional,
    Tuple,
    Dict,
    Any,
)

from helios.protocol.common.datastructures import HashFragmentBundle
from hvm.rlp.headers import BlockHeader
from hvm.rlp.consensus import NodeStakingScore

from helios.protocol.common.trackers import BasePerformanceTracker
from helios.protocol.common.types import (
    BlockBodyBundles,
    NodeDataBundles,
    ReceiptsBundles,
)
from helios.utils.headers import sequence_builder

from .requests import (
    GetBlockBodiesRequest,
    GetBlockHeadersRequest,
    GetNodeDataRequest,
    GetReceiptsRequest,
    GetBlocksRequest,
    GetNodeStakingScoreRequest,
    GetHashFragmentsRequest, GetChainsRequest, GetChainSegmentRequest)

from helios.rlp_templates.hls import P2PBlock

BaseGetBlockHeadersTracker = BasePerformanceTracker[
    GetBlockHeadersRequest,
    Tuple[BlockHeader, ...],
]


class GetBlockHeadersTracker(BaseGetBlockHeadersTracker):
    def _get_request_size(self, request: GetBlockHeadersRequest) -> int:
        payload = request.command_payload
        if isinstance(payload['block_number_or_hash'], int):
            return len(sequence_builder(
                start_number=payload['block_number_or_hash'],
                max_length=payload['max_headers'],
                skip=payload['skip'],
                reverse=payload['reverse'],
            ))
        else:
            return None

    def _get_result_size(self, result: Tuple[BlockHeader, ...]) -> Optional[int]:
        return len(result)

    def _get_result_item_count(self, result: Tuple[BlockHeader, ...]) -> int:
        return len(result)


class GetBlockBodiesTracker(BasePerformanceTracker[GetBlockBodiesRequest, BlockBodyBundles]):
    def _get_request_size(self, request: GetBlockBodiesRequest) -> Optional[int]:
        return len(request.command_payload)

    def _get_result_size(self, result: BlockBodyBundles) -> int:
        return len(result)

    def _get_result_item_count(self, result: BlockBodyBundles) -> int:
        return sum(
            len(body.uncles) + len(body.transactions)
            for body, trie_data, uncles_hash
            in result
        )


class GetReceiptsTracker(BasePerformanceTracker[GetReceiptsRequest, ReceiptsBundles]):
    def _get_request_size(self, request: GetReceiptsRequest) -> Optional[int]:
        return len(request.command_payload)

    def _get_result_size(self, result: ReceiptsBundles) -> int:
        return len(result)

    def _get_result_item_count(self, result: ReceiptsBundles) -> int:
        return sum(
            len(receipts)
            for receipts, trie_data
            in result
        )


class GetNodeDataTracker(BasePerformanceTracker[GetNodeDataRequest, NodeDataBundles]):
    def _get_request_size(self, request: GetNodeDataRequest) -> Optional[int]:
        return len(request.command_payload)

    def _get_result_size(self, result: NodeDataBundles) -> int:
        return len(result)

    def _get_result_item_count(self, result: NodeDataBundles) -> int:
        return len(result)


BaseGetBlocksTracker = BasePerformanceTracker[
    GetBlocksRequest,
    Tuple[P2PBlock, ...],
]

class GetBlocksTracker(BaseGetBlocksTracker):
    def _get_request_size(self, request: GetBlocksRequest) -> Optional[int]:
        return len(request.command_payload)

    def _get_result_size(self, result: Tuple[P2PBlock, ...]) -> int:
        return len(result)

    def _get_result_item_count(self, result: Tuple[P2PBlock, ...]) -> int:
        return len(result)

BaseGetChainSegmentTracker = BasePerformanceTracker[
    GetChainSegmentRequest,
    Tuple[P2PBlock, ...],
]

class GetChainSegmentTracker(BaseGetChainSegmentTracker):
    def _get_request_size(self, request: GetChainSegmentRequest) -> Optional[int]:
        num_blocks = request.command_payload['block_number_end'] - request.command_payload['block_number_start']
        if num_blocks == 0:
            #this is usually the whole chain
            return None
        return num_blocks

    def _get_result_size(self, result: Tuple[P2PBlock, ...]) -> int:
        return len(result)

    def _get_result_item_count(self, result: Tuple[P2PBlock, ...]) -> int:
        return len(result)

BaseGetChainsTracker = BasePerformanceTracker[
    GetChainsRequest,
    Tuple[Tuple[P2PBlock], ...],
]

class GetChainsTracker(BaseGetChainsTracker):
    def _get_request_size(self, request: GetChainsRequest) -> int:
        return len(request.command_payload['idx_list'])

    def _get_result_size(self, result: Tuple[Tuple[P2PBlock], ...]) -> int:
        return len(result)

    def _get_result_item_count(self, result: Tuple[Tuple[P2PBlock], ...]) -> int:
        return len(result)


BaseGetNodeStakingScoreTracker = BasePerformanceTracker[
    GetNodeStakingScoreRequest,
    NodeStakingScore,
]

class GetNodeStakingScoreTracker(BaseGetNodeStakingScoreTracker):
    def _get_request_size(self, request: GetNodeStakingScoreRequest) -> Optional[int]:
        return 1

    def _get_result_size(self, result: NodeStakingScore) -> int:
        return len(result)

    def _get_result_item_count(self, result: NodeStakingScore) -> int:
        return len(result)


BaseGetHashFragmentsTracker = BasePerformanceTracker[
    GetHashFragmentsRequest,
    HashFragmentBundle,
]

class GetHashFragmentsTracker(BaseGetHashFragmentsTracker):
    def _get_request_size(self, request) -> Optional[int]:
        #return None if we don't know how many to expect
        if request.command_payload['entire_window'] == False:
            return len(request.command_payload['only_these_indices'])

    def _get_result_size(self, result: HashFragmentBundle) -> int:
        return len(result.fragments)

    def _get_result_item_count(self, result: HashFragmentBundle) -> int:
        return len(result.fragments)