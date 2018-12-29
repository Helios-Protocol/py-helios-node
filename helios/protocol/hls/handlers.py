from helios.protocol.common.handlers import (
    BaseExchangeHandler,
)

from .exchanges import (
    # GetBlockBodiesExchange,
    # GetBlockHeadersExchange,
    # GetNodeDataExchange,
    # GetReceiptsExchange,
    GetBlocksExchange,
    GetNodeStakingScoreExchange,
    GetHashFragmentsExchange, GetChainsExchange, GetChainSegmentExchange)


class HLSExchangeHandler(BaseExchangeHandler):
    # _exchange_config = {
    #     'get_block_bodies': GetBlockBodiesExchange,
    #     'get_block_headers': GetBlockHeadersExchange,
    #     'get_node_data': GetNodeDataExchange,
    #     'get_receipts': GetReceiptsExchange,
    # }
    #
    # # These are needed only to please mypy.
    # get_block_bodies: GetBlockBodiesExchange
    # get_block_headers: GetBlockHeadersExchange
    # get_node_data: GetNodeDataExchange
    # get_receipts: GetReceiptsExchange


    _exchange_config = {
        'get_blocks': GetBlocksExchange,
        'get_node_staking_score': GetNodeStakingScoreExchange,
        'get_hash_fragments': GetHashFragmentsExchange,
        'get_chains': GetChainsExchange,
        'get_chain_segment': GetChainSegmentExchange,
    }

    # These are needed only to please mypy.
    get_blocks: GetBlocksExchange
    get_node_staking_score: GetNodeStakingScoreExchange
    get_hash_fragments: GetHashFragmentsExchange
    get_chains: GetChainsExchange
    get_chain_segment: GetChainSegmentExchange
