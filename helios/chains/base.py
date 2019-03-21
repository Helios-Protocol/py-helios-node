# Typeshed definitions for multiprocessing.managers is incomplete, so ignore them for now:
# https://github.com/python/typeshed/blob/85a788dbcaa5e9e9a62e55f15d44530cd28ba830/stdlib/3/multiprocessing/managers.pyi#L3
from multiprocessing.managers import (  # type: ignore
    BaseProxy,
)

from helios.utils.mp import (
    async_method,
    sync_method,
)
# from hvm.chains.base import BaseChain
# from helios.chains.coro import AsyncChainMixin
#
# class BaseAsyncChain(BaseChain, AsyncChainMixin):
#     pass

class ChainProxy(BaseProxy):
    coro_import_block = async_method('import_block')
    coro_import_chain = async_method('import_chain')


    coro_get_all_chronological_blocks_for_window = async_method('get_all_chronological_blocks_for_window')
    coro_import_chronological_block_window = async_method('import_chronological_block_window')
    coro_update_current_network_tpc_capability = async_method('update_current_network_tpc_capability')
    coro_get_local_tpc_cap = async_method('get_local_tpc_cap')
    coro_re_initialize_historical_minimum_gas_price_at_genesis = async_method('re_initialize_historical_minimum_gas_price_at_genesis')
    coro_import_current_queue_block_with_reward = async_method('import_current_queue_block_with_reward')
    coro_get_receipts = async_method('get_receipts')
    coro_get_block_by_hash = async_method('get_block_by_hash')
    coro_get_block_by_header = async_method('get_block_by_header')
    coro_get_block_by_number = async_method('get_block_by_number')
    coro_get_blocks_on_chain = async_method('get_blocks_on_chain')
    coro_get_all_blocks_on_chain = async_method('get_all_blocks_on_chain')
    coro_get_all_blocks_on_chain_by_head_block_hash = async_method('get_all_blocks_on_chain_by_head_block_hash')
    coro_get_blocks_on_chain_up_to_block_hash = async_method('get_blocks_on_chain_up_to_block_hash')


    import_block = sync_method('import_block')
    import_chain = sync_method('import_chain')


    get_vm = sync_method('get_vm')
    get_all_chronological_blocks_for_window = sync_method('get_all_chronological_blocks_for_window')
    import_chronological_block_window = sync_method('import_chronological_block_window')
    update_current_network_tpc_capability = sync_method('update_current_network_tpc_capability')
    get_local_tpc_cap = sync_method('get_local_tpc_cap')
    validate_block_specification = sync_method('validate_block_specification')
    re_initialize_historical_minimum_gas_price_at_genesis = sync_method('re_initialize_historical_minimum_gas_price_at_genesis')
    get_new_block_hash_to_test_peer_node_health = sync_method('get_new_block_hash_to_test_peer_node_health')
    get_genesis_block_hash = sync_method('get_genesis_block_hash')
    get_genesis_wallet_address = sync_method('get_genesis_wallet_address')

    get_receipts = sync_method('get_genesis_wallet_address')

    get_vm_configuration = sync_method('get_vm_configuration')
    get_vm_class = sync_method('get_vm_class')
    get_vm_class_for_timestamp = sync_method('get_vm_class_for_block_number')

    import_block_with_profiler = sync_method('import_block_with_profiler')