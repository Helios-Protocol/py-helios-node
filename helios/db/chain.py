# Typeshed definitions for multiprocessing.managers is incomplete, so ignore them for now:
# https://github.com/python/typeshed/blob/85a788dbcaa5e9e9a62e55f15d44530cd28ba830/stdlib/3/multiprocessing/managers.pyi#L3
from multiprocessing.managers import (  # type: ignore
    BaseProxy,
)
from typing import (
    Dict,
    Iterable,
    List,
    Tuple,
    Type,
    Optional,
    Union,
)
from hvm.types import Timestamp

from eth_typing import Hash32, BlockNumber, Address

from hvm.db.chain import ChainDB
from hvm.rlp.blocks import BaseBlock
from hvm.rlp.headers import BlockHeader
from hvm.rlp.receipts import Receipt
from hvm.rlp.transactions import BaseTransaction

#from helios.db.header import AsyncHeaderDB
from helios.utils.mp import (
    async_method,
    sync_method,
)


class AsyncChainDB(ChainDB):
    async def coro_get(self, key: bytes) -> bytes:
        raise NotImplementedError()

    async def coro_persist_block(self, block: BaseBlock) -> None:
        raise NotImplementedError()

    async def coro_persist_uncles(self, uncles: Tuple[BlockHeader]) -> Hash32:
        raise NotImplementedError()

    async def coro_persist_trie_data_dict(self, trie_data_dict: Dict[bytes, bytes]) -> None:
        raise NotImplementedError()

    async def coro_get_block_transactions(
            self,
            header: BlockHeader,
            transaction_class: Type[BaseTransaction]) -> Iterable[BaseTransaction]:
        raise NotImplementedError()

    async def coro_get_block_uncles(self, uncles_hash: Hash32) -> List[BlockHeader]:
        raise NotImplementedError()

    async def coro_get_receipts(
            self, header: BlockHeader, receipt_class: Type[Receipt]) -> List[Receipt]:
        raise NotImplementedError()


    async def coro_get_canonical_block_hash(self, block_number: BlockNumber, wallet_address: Address) -> Hash32:
        raise NotImplementedError("ChainDB classes must implement this method")

    async def coro_get_canonical_block_header_by_number(self, block_number: BlockNumber, wallet_address:Address) -> BlockHeader:  # noqa: E501
        raise NotImplementedError("ChainDB classes must implement this method")

    async def coro_get_canonical_head_hash(self, wallet_address: Address = None) -> Hash32:
        raise NotImplementedError("ChainDB classes must implement this method")

    async def coro_get_canonical_head(self, wallet_address: Address) -> BlockHeader:
        raise NotImplementedError("ChainDB classes must implement this method")

    async def coro_get_block_header_by_hash(self, block_hash: Hash32) -> BlockHeader:
        raise NotImplementedError("ChainDB classes must implement this method")

    async def coro_get_score(self, block_hash: Hash32) -> int:
        raise NotImplementedError("ChainDB classes must implement this method")

    async def coro_header_exists(self, block_hash: Hash32) -> bool:
        raise NotImplementedError("ChainDB classes must implement this method")

    async def coro_persist_header(self, header: BlockHeader) -> Tuple[BlockHeader, ...]:
        raise NotImplementedError("ChainDB classes must implement this method")

    async def coro_persist_header_chain(self,
                                        headers: Iterable[BlockHeader]) -> Tuple[BlockHeader, ...]:
        raise NotImplementedError("ChainDB classes must implement this method")

    async def coro_load_historical_minimum_gas_price(self, mutable:bool = True, sort:bool = False) -> Optional[List[List[Union[Timestamp, int]]]]:
        raise NotImplementedError()

    async def coro_load_historical_network_tpc_capability(self, mutable:bool = True, sort:bool = False) -> Optional[List[List[Union[Timestamp, int]]]]:
        raise NotImplementedError()

    async def coro_save_historical_minimum_gas_price(self, historical_minimum_gas_price: List[List[Union[Timestamp, int]]]) -> None:
        raise NotImplementedError()

    async def coro_save_historical_network_tpc_capability(self, historical_tpc_capability: List[List[Union[Timestamp, int]]], de_sparse: bool = False) -> None:
        raise NotImplementedError()

    async def coro_get_latest_reward_block_number(self, wallet_address: Address) -> BlockNumber:
        raise NotImplementedError()

    async def coro_get_all_block_hashes_on_chain(self, chain_address: Address) -> List[Hash32]:
        raise NotImplementedError()

    async def coro_get_all_block_hashes_on_chain_by_head_block_hash(self, chain_head_hash: Hash32) -> List[Hash32]:
        raise NotImplementedError()



class ChainDBProxy(BaseProxy):
    coro_get_block_header_by_hash = async_method('get_block_header_by_hash')
    coro_get_canonical_head = async_method('get_canonical_head')
    coro_get_canonical_head_hash = async_method('get_canonical_head_hash')
    coro_get_score = async_method('get_score')
    coro_header_exists = async_method('header_exists')
    coro_get_canonical_block_hash = async_method('get_canonical_block_hash')
    coro_get_canonical_block_header_by_number = async_method('get_canonical_block_header_by_number')
    coro_persist_header = async_method('persist_header')
    coro_persist_uncles = async_method('persist_uncles')
    coro_persist_trie_data_dict = async_method('persist_trie_data_dict')
    coro_get_block_transactions = async_method('get_block_transactions')
    coro_get_block_uncles = async_method('get_block_uncles')
    coro_get_receipts = async_method('get_receipts')
    coro_get_chain_wallet_address_for_block_hash = async_method('get_chain_wallet_address_for_block_hash')
    coro_min_gas_system_initialization_required = async_method('min_gas_system_initialization_required')
    coro_load_historical_network_tpc_capability = async_method('load_historical_network_tpc_capability')
    coro_load_historical_minimum_gas_price = async_method('load_historical_minimum_gas_price')
    coro_save_historical_minimum_gas_price = async_method('save_historical_minimum_gas_price')
    coro_save_historical_network_tpc_capability = async_method('save_historical_network_tpc_capability')
    coro_load_historical_tx_per_centisecond = async_method('load_historical_tx_per_centisecond')
    coro_get_required_block_min_gas_price = async_method('get_required_block_min_gas_price')
    coro_initialize_historical_minimum_gas_price_at_genesis = async_method(
        'initialize_historical_minimum_gas_price_at_genesis')
    coro_get_latest_reward_block_number = async_method('get_latest_reward_block_number')
    coro_get_all_block_hashes_on_chain = async_method('get_all_block_hashes_on_chain')
    coro_get_all_block_hashes_on_chain_by_head_block_hash = async_method('get_all_block_hashes_on_chain_by_head_block_hash')
    coro_get_block_stake_from_children = async_method('get_block_stake_from_children')
    coro_get_mature_stake = async_method('get_mature_stake')

    get_block_header_by_hash = sync_method('get_block_header_by_hash')
    get_canonical_head = sync_method('get_canonical_head')
    get_score = sync_method('get_score')
    header_exists = sync_method('header_exists')
    get_canonical_block_hash = sync_method('get_canonical_block_hash')
    persist_header = sync_method('persist_header')
    persist_uncles = sync_method('persist_uncles')
    persist_trie_data_dict = sync_method('persist_trie_data_dict')
    get_chain_wallet_address_for_block_hash = sync_method('get_chain_wallet_address_for_block_hash')
    min_gas_system_initialization_required = sync_method('min_gas_system_initialization_required')
    load_historical_network_tpc_capability = sync_method('load_historical_network_tpc_capability')
    load_historical_minimum_gas_price = sync_method('load_historical_minimum_gas_price')
    save_historical_minimum_gas_price = sync_method('save_historical_minimum_gas_price')
    save_historical_network_tpc_capability = sync_method('save_historical_network_tpc_capability')
    load_historical_tx_per_centisecond = sync_method('load_historical_tx_per_centisecond')
    get_required_block_min_gas_price = sync_method('get_required_block_min_gas_price')
    initialize_historical_minimum_gas_price_at_genesis = sync_method(
        'initialize_historical_minimum_gas_price_at_genesis')
    get_latest_reward_block_number = sync_method('get_latest_reward_block_number')
    get_canonical_block_header_by_number = sync_method('get_canonical_block_header_by_number')

    get_all_block_hashes_on_chain = sync_method('get_all_block_hashes_on_chain')

    get_block_stake_from_children = sync_method('get_block_stake_from_children')
    get_mature_stake = sync_method('get_mature_stake')
