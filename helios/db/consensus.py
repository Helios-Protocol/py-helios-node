# Typeshed definitions for multiprocessing.managers is incomplete, so ignore them for now:
# https://github.com/python/typeshed/blob/85a788dbcaa5e9e9a62e55f15d44530cd28ba830/stdlib/3/multiprocessing/managers.pyi#L3
from multiprocessing.managers import (  # type: ignore
    BaseProxy,
)
from hvm.db.consensus import ConsensusDB

from helios.utils.mp import (
    async_method,
    sync_method,
)
from hvm.rlp.consensus import NodeStakingScore

from eth_typing import Address, BlockNumber

from eth_keys.datatypes import PrivateKey

class AsyncConsensusDB(ConsensusDB):

    async def coro_get_signed_peer_score(self, private_key: PrivateKey,
                              peer_wallet_address: Address,
                              after_block_number: BlockNumber = None,
                              ) -> NodeStakingScore:
        raise NotImplementedError()

    async def coro_get_signed_peer_score_string_private_key(self, private_key_string: bytes,
                                                            network_id: int,
                                                            peer_wallet_address: Address,
                                                            after_block_number: BlockNumber = None,
                                                            ) -> NodeStakingScore:
        raise NotImplementedError()

class ConsensusDBProxy(BaseProxy):

    coro_get_signed_peer_score = async_method('get_signed_peer_score')
    coro_get_signed_peer_score_string_private_key = async_method('get_signed_peer_score_string_private_key')
    coro_validate_node_staking_score = async_method('validate_node_staking_score')



    save_health_request = sync_method('save_health_request')
    get_current_peer_node_health = sync_method('get_current_peer_node_health')
    get_signed_peer_score = sync_method('get_signed_peer_score')
    get_signed_peer_score_string_private_key = sync_method('get_signed_peer_score_string_private_key')
    validate_node_staking_score = sync_method('validate_node_staking_score')

    get_timestamp_of_last_health_request = sync_method('get_timestamp_of_last_health_request')