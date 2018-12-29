from typing import (
    Any,
    Dict,
    Tuple,
    Optional,
    List,
)

from helios.protocol.common.datastructures import HashFragmentBundle
from helios.protocol.hls.commands import GetChains
from hvm.types import Timestamp
from eth_typing import (
    BlockIdentifier,
    Hash32,
    BlockNumber,
    Address,
)
from hvm.rlp.headers import BlockHeader
from hvm.rlp.consensus import NodeStakingScore

from hvm.db.consensus import ConsensusDB

from helios.protocol.common.exchanges import (
    BaseExchange,
)
from helios.protocol.common.normalizers import (
    NoopNormalizer,
)
from helios.protocol.common.validators import (
    noop_payload_validator,
    NoopResultValidator)
from helios.protocol.common.types import (
    BlockBodyBundles,
    NodeDataBundles,
    ReceiptsByBlock,
    ReceiptsBundles,
)
from helios.rlp_templates.hls import (
    BlockBody,
    P2PBlock,
)

from .normalizers import (
    GetBlockBodiesNormalizer,
    GetNodeDataNormalizer,
    ReceiptsNormalizer,
    GetNodeStakingScoreNormalizer, GetHashFragmentsNormalizer, GetChainsNormalizer)
from .requests import (
    GetBlockBodiesRequest,
    GetBlockHeadersRequest,
    GetNodeDataRequest,
    GetReceiptsRequest,
    GetBlocksRequest,
    GetNodeStakingScoreRequest,

    GetHashFragmentsRequest, GetChainsRequest, GetChainSegmentRequest)
from .trackers import (
    GetBlockHeadersTracker,
    GetBlockBodiesTracker,
    GetNodeDataTracker,
    GetReceiptsTracker,
    GetBlocksTracker,
    GetNodeStakingScoreTracker,
    GetHashFragmentsTracker, GetChainsTracker, GetChainSegmentTracker)
from .validators import (
    GetBlockBodiesValidator,
    GetBlockHeadersValidator,
    GetNodeDataValidator,
    ReceiptsValidator,
    GetBlocksValidator,
    GetNodeStakingScoreValidator,
    get_hash_fragments_payload_validator, GetChainsValidator, GetChainSegmentValidator)



BaseGetBlockHeadersExchange = BaseExchange[
    Dict[str, Any],
    Tuple[BlockHeader, ...],
    Tuple[BlockHeader, ...],
]

class GetBlockHeadersExchange(BaseGetBlockHeadersExchange):
    _normalizer = NoopNormalizer[Tuple[BlockHeader, ...]]()
    request_class = GetBlockHeadersRequest
    tracker_class = GetBlockHeadersTracker

    async def __call__(  # type: ignore
            self,
            block_number_or_hash: BlockIdentifier,
            max_headers: int = None,
            skip: int = 0,
            reverse: bool = True,
            timeout: float = None) -> Tuple[BlockHeader, ...]:

        original_request_args = (block_number_or_hash, max_headers, skip, reverse)
        validator = GetBlockHeadersValidator(*original_request_args)
        request = self.request_class(*original_request_args)

        return await self.get_result(
            request,
            self._normalizer,
            validator,
            noop_payload_validator,
            timeout,
        )


BaseNodeDataExchange = BaseExchange[Tuple[Hash32, ...], Tuple[bytes, ...], NodeDataBundles]


class GetNodeDataExchange(BaseNodeDataExchange):
    _normalizer = GetNodeDataNormalizer()
    request_class = GetNodeDataRequest
    tracker_class = GetNodeDataTracker

    async def __call__(self,  # type: ignore
                       node_hashes: Tuple[Hash32, ...],
                       timeout: float = None) -> NodeDataBundles:
        validator = GetNodeDataValidator(node_hashes)
        request = self.request_class(node_hashes)
        return await self.get_result(
            request,
            self._normalizer,
            validator,
            noop_payload_validator,
            timeout,
        )


class GetReceiptsExchange(BaseExchange[Tuple[Hash32, ...], ReceiptsByBlock, ReceiptsBundles]):
    _normalizer = ReceiptsNormalizer()
    request_class = GetReceiptsRequest
    tracker_class = GetReceiptsTracker

    async def __call__(self,  # type: ignore
                       headers: Tuple[BlockHeader, ...],
                       timeout: float = None) -> ReceiptsBundles:  # type: ignore
        validator = ReceiptsValidator(headers)

        block_hashes = tuple(header.hash for header in headers)
        request = self.request_class(block_hashes)

        return await self.get_result(
            request,
            self._normalizer,
            validator,
            noop_payload_validator,
            timeout,
        )


BaseGetBlockBodiesExchange = BaseExchange[
    Tuple[Hash32, ...],
    Tuple[BlockBody, ...],
    BlockBodyBundles,
]


class GetBlockBodiesExchange(BaseGetBlockBodiesExchange):
    _normalizer = GetBlockBodiesNormalizer()
    request_class = GetBlockBodiesRequest
    tracker_class = GetBlockBodiesTracker

    async def __call__(self,  # type: ignore
                       headers: Tuple[BlockHeader, ...],
                       timeout: float = None) -> BlockBodyBundles:
        validator = GetBlockBodiesValidator(headers)

        block_hashes = tuple(header.hash for header in headers)
        request = self.request_class(block_hashes)

        return await self.get_result(
            request,
            self._normalizer,
            validator,
            noop_payload_validator,
            timeout,
        )



BaseGetBlocksExchange = BaseExchange[
    Tuple[Hash32, ...], #parameter types for request_class
    Tuple[P2PBlock, ...], #type that rlp returns
    Tuple[P2PBlock, ...], #type that the normalizer returns
]

#if rlp and normalizer return same type, use NoobNormalizer. It does nothing.


class GetBlocksExchange(BaseGetBlocksExchange):
    _normalizer = NoopNormalizer[Tuple[P2PBlock, ...]]()
    request_class = GetBlocksRequest
    tracker_class = GetBlocksTracker

    async def __call__(  # type: ignore
            self,
            block_hashes: Tuple[Hash32, ...],
            timeout: float = None) -> Tuple[P2PBlock, ...]:

        validator = GetBlocksValidator(block_hashes)
        request = self.request_class(block_hashes)

        return await self.get_result(
            request,
            self._normalizer,
            validator,
            noop_payload_validator,
            timeout,
        )

BaseGetChainSegmentExchange = BaseExchange[
    Dict[str, Any], #parameter types for request_class
    Tuple[P2PBlock, ...], #type that rlp returns
    Tuple[P2PBlock, ...], #type that the normalizer returns
]

#if rlp and normalizer return same type, use NoobNormalizer. It does nothing.


class GetChainSegmentExchange(BaseGetChainSegmentExchange):
    _normalizer = NoopNormalizer[Tuple[P2PBlock, ...]]()
    request_class = GetChainSegmentRequest
    tracker_class = GetChainSegmentTracker

    async def __call__(  # type: ignore
            self,
            chain_address: Address,
            block_number_start: int = 0,
            block_number_end: int = 0,
            timeout: float = None) -> Tuple[P2PBlock, ...]:

        validator = GetChainSegmentValidator(chain_address)
        request = self.request_class(chain_address, block_number_start, block_number_end)

        return await self.get_result(
            request,
            self._normalizer,
            validator,
            noop_payload_validator,
            timeout,
        )


BaseGetChainsExchange = BaseExchange[
    Dict[str, Any], #parameter types for request_class
    Tuple[List[P2PBlock], ...], #type that rlp returns
    Tuple[List[P2PBlock], ...], #type that the normalizer returns
]

#if rlp and normalizer return same type, use NoobNormalizer. It does nothing.


class GetChainsExchange(BaseGetChainsExchange):
    _normalizer = GetChainsNormalizer()
    request_class = GetChainsRequest
    tracker_class = GetChainsTracker

    async def __call__(  # type: ignore
            self,
            timestamp: Timestamp,
            idx_list: List[int],
            expected_chain_head_hash_fragments: List[bytes],
            timeout: float = None) -> Tuple[Tuple[P2PBlock], ...]:

        validator = GetChainsValidator(expected_chain_head_hash_fragments)
        request = self.request_class(timestamp, idx_list)

        return await self.get_result(
            request,
            self._normalizer,
            validator,
            noop_payload_validator,
            timeout,
        )


BaseGetNodeStakingScoreExchange = BaseExchange[
    BlockNumber, #parameter types for request_class
    NodeStakingScore, #type that rlp returns
    NodeStakingScore, #type that the normalizer returns
]

class GetNodeStakingScoreExchange(BaseGetNodeStakingScoreExchange):
    _normalizer = GetNodeStakingScoreNormalizer()
    request_class = GetNodeStakingScoreRequest
    tracker_class = GetNodeStakingScoreTracker

    async def __call__(  # type: ignore
            self,
            since_block: BlockNumber,
            consensus_db: ConsensusDB,
            timeout: float = None) -> NodeStakingScore:

        validator = GetNodeStakingScoreValidator(since_block, consensus_db)
        request = self.request_class(since_block)

        return await self.get_result(
            request,
            self._normalizer,
            validator,
            noop_payload_validator,
            timeout,
        )


BaseGetHashFragmentsExchange = BaseExchange[
    Dict[str, Any],  #parameter types for request_class
    Dict[str, Any],  #type that rlp returns
    HashFragmentBundle, #type that the normalizer returns
]

#hash type ids: 1: chronological block hashes. In this case the timestamp is the timestamp of the chronological block hash window.
# 2: chain head block hashes. In this case, the timestamp is the chronological chain head root hash timestamp.
class GetHashFragmentsExchange(BaseGetHashFragmentsExchange):
    _normalizer = GetHashFragmentsNormalizer()
    request_class = GetHashFragmentsRequest
    tracker_class = GetHashFragmentsTracker

    async def __call__(  # type: ignore
            self,
            timestamp: Timestamp,
            fragment_length: int = 32,
            only_these_indices: Optional[List[int]] = None, #None sends all hashes in window
            hash_type_id: int = 1,
            timeout: float = None) -> HashFragmentBundle:

        result_validator = NoopResultValidator() #this gets called after the normalizer

        # this gets called before the normalizer. Therefore, we can validate the payload, and then strip out any
        # validation data that is no longer needed in the normalization function.
        payload_validator = get_hash_fragments_payload_validator
        request = self.request_class(timestamp, fragment_length, only_these_indices, hash_type_id)

        return await self.get_result(
            request,
            self._normalizer,
            result_validator,
            payload_validator,
            timeout,
        )




