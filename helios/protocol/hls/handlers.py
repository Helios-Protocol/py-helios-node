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
    GetHashFragmentsExchange, GetChainsExchange, GetChainSegmentExchange, GetMinGasParametersExchange)


class HLSExchangeHandler(BaseExchangeHandler):

    _exchange_config = {
        'get_blocks': GetBlocksExchange,
        'get_node_staking_score': GetNodeStakingScoreExchange,
        'get_hash_fragments': GetHashFragmentsExchange,
        'get_chains': GetChainsExchange,
        'get_chain_segment': GetChainSegmentExchange,
        'get_min_gas_parameters': GetMinGasParametersExchange,
    }

    # These are needed only to please mypy.
    get_blocks: GetBlocksExchange
    get_node_staking_score: GetNodeStakingScoreExchange
    get_hash_fragments: GetHashFragmentsExchange
    get_chains: GetChainsExchange
    get_chain_segment: GetChainSegmentExchange
    get_min_gas_parameters: GetMinGasParametersExchange
