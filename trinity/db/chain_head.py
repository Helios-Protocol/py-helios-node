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
    def get_root_hash(self, timestamp = None):
        if timestamp is None:
            return self.root_hash
        else:
            return self.get_root_hash_saved_at_timestamp(self.db, timestamp)
    
    

class ChainHeadDBProxy(BaseProxy):
    coro_load_from_saved_root_hash_at_timestamp = async_method('load_from_saved_root_hash_at_timestamp')
    coro_get_root_hash = async_method('get_root_hash')

    load_from_saved_root_hash_at_timestamp = sync_method('load_from_saved_root_hash_at_timestamp')
    get_root_hash = sync_method('get_root_hash')
