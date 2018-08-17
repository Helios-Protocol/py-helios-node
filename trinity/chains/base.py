# Typeshed definitions for multiprocessing.managers is incomplete, so ignore them for now:
# https://github.com/python/typeshed/blob/85a788dbcaa5e9e9a62e55f15d44530cd28ba830/stdlib/3/multiprocessing/managers.pyi#L3
from multiprocessing.managers import (  # type: ignore
    BaseProxy,
)

from trinity.utils.mp import (
    async_method,
    sync_method,
)

class ChainProxy(BaseProxy):
    coro_import_block = async_method('import_block')
    coro_import_chain = async_method('import_chain')
    coro_get_block_stake_from_children = async_method('get_block_stake_from_children')
    coro_get_mature_stake = async_method('get_mature_stake')
    coro_get_all_chronological_blocks_for_window = async_method('get_all_chronological_blocks_for_window')
    coro_import_chronological_block_window = async_method('import_chronological_block_window')
    coro_update_current_network_tpc_capability = async_method('update_current_network_tpc_capability')
    coro_get_local_tpc_cap = async_method('get_local_tpc_cap')
    
    
    import_block = sync_method('import_block')
    import_chain = sync_method('import_chain')
    get_block_stake_from_children = sync_method('get_block_stake_from_children')
    get_mature_stake = sync_method('get_mature_stake')
    get_vm = sync_method('get_vm')
    get_all_chronological_blocks_for_window = sync_method('get_all_chronological_blocks_for_window')
    import_chronological_block_window = sync_method('import_chronological_block_window')
    update_current_network_tpc_capability = sync_method('update_current_network_tpc_capability')
    get_local_tpc_cap = sync_method('get_local_tpc_cap')