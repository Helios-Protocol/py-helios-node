from helios.utils.async_dispatch import (
    async_method,
)
from hvm.rlp.headers import BlockHeader
from hvm.rlp.blocks import BaseBlock
from hvm.rlp.consensus import NodeStakingScore
from typing import (
    List,
)
from hvm.types import Timestamp
from eth_typing import (
    Hash32,
    Address,
    BlockNumber,
)
from hvm.chains.base import BaseChain


# When extending the actual chain class, make sure this is the last parameter so it doesnt overrride the real definitions
class AsyncChain(BaseChain):

    async def coro_import_block(self,
                                block: BlockHeader,
                                perform_validation: bool=True) -> BaseBlock:
        raise NotImplementedError()

    async def coro_import_chain(self, block_list: List[BaseBlock], perform_validation: bool=True, save_block_head_hash_timestamp: bool = True, allow_replacement: bool = True) -> None:
        raise NotImplementedError()


    async def coro_get_all_chronological_blocks_for_window(self, window_timestamp: Timestamp) -> List[BaseBlock]:
        raise NotImplementedError()

    async def coro_import_chronological_block_window(self, block_list: List[BaseBlock], window_start_timestamp: Timestamp,
                                          save_block_head_hash_timestamp: bool = True,
                                          allow_unprocessed: bool = False) -> None:
        raise NotImplementedError()

    async def coro_update_current_network_tpc_capability(self, current_network_tpc_cap: int,
                                              update_min_gas_price: bool = True) -> None:
        raise NotImplementedError()

    async def coro_get_local_tpc_cap(self) -> int:
        raise NotImplementedError()

    async def coro_re_initialize_historical_minimum_gas_price_at_genesis(self) -> None:
        raise NotImplementedError()

    async def coro_import_current_queue_block_with_reward(self, node_staking_score_list: List[NodeStakingScore] = None) -> BaseBlock:
        raise NotImplementedError()

    async def coro_get_block_by_hash(self, block_hash: Hash32) -> BaseBlock:
        raise NotImplementedError("Chain classes must implement this method")

    async def coro_get_block_by_header(self, block_header: BlockHeader) -> BaseBlock:
        raise NotImplementedError("Chain classes must implement this method")

    async def coro_get_block_by_number(self, block_number: BlockNumber, chain_address: Address = None) -> BaseBlock:
        raise NotImplementedError("Chain classes must implement this method")

    async def coro_get_blocks_on_chain(self, start: int, end: int, chain_address: Address = None) -> List[BaseBlock]:
        raise NotImplementedError("Chain classes must implement this method")

    async def coro_get_all_blocks_on_chain(self, chain_address: Address = None) -> List[BaseBlock]:
        raise NotImplementedError("Chain classes must implement this method")

    async def coro_get_all_blocks_on_chain_by_head_block_hash(self, chain_head_hash: Hash32) -> List[BaseBlock]:
        raise NotImplementedError("Chain classes must implement this method")

    async def coro_get_blocks_on_chain_up_to_block_hash(self, chain_head_hash: Hash32) -> List[BaseBlock]:
        raise NotImplementedError("Chain classes must implement this method")

    async def coro_get_new_block_hash_to_test_peer_node_health(self) -> Hash32:
        raise NotImplementedError("Chain classes must implement this method")

class AsyncChainMixin(AsyncChain):

    coro_get_canonical_block_by_number = async_method('get_canonical_block_by_number')
    coro_get_block_by_header = async_method('get_block_by_header')
    coro_import_block = async_method('import_block')
    coro_get_all_chronological_blocks_for_window = async_method('get_all_chronological_blocks_for_window')
    coro_import_chronological_block_window = async_method('import_chronological_block_window')
    coro_update_current_network_tpc_capability = async_method('update_current_network_tpc_capability')
    coro_get_local_tpc_cap = async_method('get_local_tpc_cap')
    coro_re_initialize_historical_minimum_gas_price_at_genesis = async_method(
        're_initialize_historical_minimum_gas_price_at_genesis')
    coro_get_all_blocks_on_chain = async_method('get_all_blocks_on_chain')
    coro_get_all_blocks_on_chain_by_head_block_hash = async_method('get_all_blocks_on_chain_by_head_block_hash')


    coro_import_chain = async_method('import_chain')
    coro_import_current_queue_block_with_reward = async_method('import_current_queue_block_with_reward')
    coro_get_block_by_hash = async_method('get_block_by_hash')
    coro_get_blocks_on_chain = async_method('get_blocks_on_chain')
    coro_get_blocks_on_chain_up_to_block_hash = async_method('get_blocks_on_chain_up_to_block_hash')
    coro_get_block_by_number = async_method('get_block_by_number')
    coro_import_current_queue_block = async_method('import_current_queue_block')
    coro_purge_block_and_all_children_and_set_parent_as_chain_head_by_hash = async_method('purge_block_and_all_children_and_set_parent_as_chain_head_by_hash')


    coro_get_new_block_hash_to_test_peer_node_health = async_method('get_new_block_hash_to_test_peer_node_health')




