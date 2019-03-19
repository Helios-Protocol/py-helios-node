from helios.utils.async_dispatch import (
    async_method,
)


class AsyncChainMixin:

    coro_get_canonical_block_by_number = async_method('get_canonical_block_by_number')
    coro_get_block_by_hash = async_method('get_block_by_hash')
    coro_get_block_by_header = async_method('get_block_by_header')

    coro_import_block = async_method('import_block')
    coro_import_chain = async_method('import_chain')
    coro_get_all_chronological_blocks_for_window = async_method('get_all_chronological_blocks_for_window')
    coro_import_chronological_block_window = async_method('import_chronological_block_window')
    coro_update_current_network_tpc_capability = async_method('update_current_network_tpc_capability')
    coro_get_local_tpc_cap = async_method('get_local_tpc_cap')
    coro_re_initialize_historical_minimum_gas_price_at_genesis = async_method(
        're_initialize_historical_minimum_gas_price_at_genesis')
    coro_get_block_by_number = async_method('get_block_by_number')
    coro_get_blocks_on_chain = async_method('get_blocks_on_chain')
    coro_get_all_blocks_on_chain = async_method('get_all_blocks_on_chain')
    coro_get_all_blocks_on_chain_by_head_block_hash = async_method('get_all_blocks_on_chain_by_head_block_hash')
    coro_get_blocks_on_chain_up_to_block_hash = async_method('get_blocks_on_chain_up_to_block_hash')



