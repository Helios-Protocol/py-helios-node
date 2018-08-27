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
    coro_set_current_syncing_info = async_method('set_current_syncing_info')
    coro_get_current_syncing_info = async_method('get_current_syncing_info')
    coro_get_next_head_block_hash = async_method('get_next_head_block_hash')
    coro_get_head_block_hashes = async_method('get_head_block_hashes')
    coro_set_current_syncing_last_chain = async_method('set_current_syncing_last_chain')
    coro_get_latest_timestamp = async_method('get_latest_timestamp')
    coro_get_next_n_head_block_hashes = async_method('get_next_n_head_block_hashes')
    coro_get_last_complete_historical_root_hash = async_method('get_last_complete_historical_root_hash')
    coro_get_root_hash = async_method('get_root_hash')
    coro_save_single_historical_root_hash = async_method('save_single_historical_root_hash')
    coro_get_historical_root_hash = async_method('get_historical_root_hash')
    coro_get_latest_historical_root_hash = async_method('get_latest_historical_root_hash')
    coro_get_chain_head_hash = async_method('get_chain_head_hash')
    

    get_historical_root_hashes = sync_method('get_historical_root_hashes')
    set_current_syncing_info = sync_method('set_current_syncing_info')
    get_current_syncing_info = sync_method('get_current_syncing_info')
    get_next_head_block_hash = sync_method('get_next_head_block_hash')
    get_head_block_hashes = sync_method('get_head_block_hashes')
    set_current_syncing_last_chain = sync_method('set_current_syncing_last_chain')
    get_latest_timestamp = sync_method('get_latest_timestamp')
    get_next_n_head_block_hashes = sync_method('get_next_n_head_block_hashes')
    get_last_complete_historical_root_hash = sync_method('get_last_complete_historical_root_hash')
    get_root_hash = sync_method('get_root_hash')
    save_single_historical_root_hash = sync_method('save_single_historical_root_hash')
    get_historical_root_hash = sync_method('get_historical_root_hash')
    load_saved_root_hash = sync_method('load_saved_root_hash')
    get_latest_historical_root_hash = sync_method('get_latest_historical_root_hash')
    get_chain_head_hash = sync_method('get_chain_head_hash')