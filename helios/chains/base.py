# Typeshed definitions for multiprocessing.managers is incomplete, so ignore them for now:
# https://github.com/python/typeshed/blob/85a788dbcaa5e9e9a62e55f15d44530cd28ba830/stdlib/3/multiprocessing/managers.pyi#L3
from multiprocessing.managers import (  # type: ignore
    BaseProxy,
)

from helios.utils.mp import (
    async_method,
    sync_method,
)

from hvm.chains.base import Chain


# class AsyncChain(Chain):
#     #coro_import_block = async_method('import_block')
#
#     coro_get_mature_stake

class ChainProxy(BaseProxy):
    coro_import_block = async_method('import_block')
    coro_import_chain = async_method('import_chain')
    coro_get_block_stake_from_children = async_method('get_block_stake_from_children')
    coro_get_mature_stake = async_method('get_mature_stake')
    coro_get_all_chronological_blocks_for_window = async_method('get_all_chronological_blocks_for_window')
    coro_import_chronological_block_window = async_method('import_chronological_block_window')
    coro_update_current_network_tpc_capability = async_method('update_current_network_tpc_capability')
    coro_get_local_tpc_cap = async_method('get_local_tpc_cap')
    coro_re_initialize_historical_minimum_gas_price_at_genesis = async_method('re_initialize_historical_minimum_gas_price_at_genesis')
    coro_import_current_queue_block_with_reward = async_method('import_current_queue_block_with_reward')

    import_block = sync_method('import_block')
    import_chain = sync_method('import_chain')
    get_block_stake_from_children = sync_method('get_block_stake_from_children')
    get_mature_stake = sync_method('get_mature_stake')
    get_vm = sync_method('get_vm')
    get_all_chronological_blocks_for_window = sync_method('get_all_chronological_blocks_for_window')
    import_chronological_block_window = sync_method('import_chronological_block_window')
    update_current_network_tpc_capability = sync_method('update_current_network_tpc_capability')
    get_local_tpc_cap = sync_method('get_local_tpc_cap')
    validate_block_specification = sync_method('validate_block_specification')
    re_initialize_historical_minimum_gas_price_at_genesis = sync_method('re_initialize_historical_minimum_gas_price_at_genesis')
    get_new_block_hash_to_test_peer_node_health = sync_method('get_new_block_hash_to_test_peer_node_health')




    get_vm_configuration = sync_method('get_vm_configuration')
    get_vm_class = sync_method('get_vm_class')
    get_vm_class_for_timestamp = sync_method('get_vm_class_for_block_number')

    import_block_with_profiler = sync_method('import_block_with_profiler')