# Typeshed definitions for multiprocessing.managers is incomplete, so ignore them for now:
# https://github.com/python/typeshed/blob/85a788dbcaa5e9e9a62e55f15d44530cd28ba830/stdlib/3/multiprocessing/managers.pyi#L3
from multiprocessing.managers import (  # type: ignore
    BaseProxy,
)
from evm.db.chain_head import ChainHeadDB

from trinity.utils.mp import (
    async_method,
    sync_method,
)

class AsyncChainHeadDB(ChainHeadDB):
    pass
    
    

class ChainHeadDBProxy(BaseProxy):

    coro_get_historical_root_hashes = async_method('get_historical_root_hashes')

    get_historical_root_hashes = sync_method('get_historical_root_hashes')