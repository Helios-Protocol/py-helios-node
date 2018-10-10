from helios.protocol.common.handlers import (
    BaseExchangeHandler,
)

from .exchanges import (
    # GetBlockBodiesExchange,
    # GetBlockHeadersExchange,
    # GetNodeDataExchange,
    # GetReceiptsExchange,
    GetBlocksExchange,
)


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
    }

    # These are needed only to please mypy.
    get_blocks: GetBlocksExchange
