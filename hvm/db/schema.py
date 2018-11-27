from abc import ABCMeta, abstractmethod

from hvm.constants import TIME_BETWEEN_HEAD_HASH_SAVE
from eth_typing import (
    BlockNumber,
    Hash32,
    Address,
)

from hvm.exceptions import InvalidHeadRootTimestamp


class BaseSchema(metaclass=ABCMeta):
    @staticmethod
    @abstractmethod
    def make_canonical_head_hash_lookup_key(wallet_address:Address) -> bytes:
        raise NotImplementedError('Must be implemented by subclasses')

    @staticmethod
    @abstractmethod
    def make_block_number_to_hash_lookup_key(wallet_address:Address, block_number: BlockNumber) -> bytes:
        raise NotImplementedError('Must be implemented by subclasses')

    @staticmethod
    @abstractmethod
    def make_transaction_hash_to_block_lookup_key(transaction_hash: Hash32) -> bytes:
        raise NotImplementedError('Must be implemented by subclasses')


class SchemaV1(BaseSchema):
    @staticmethod
    def make_canonical_head_hash_lookup_key(wallet_address:Address) -> bytes:
        return b'v1:canonical_head_hash:%s' % wallet_address
    
    @staticmethod
    def make_account_lookup_key(wallet_address:Address) -> bytes:
        return b'account:%s' % wallet_address

    @staticmethod
    def make_block_number_to_hash_lookup_key(wallet_address:Address, block_number: BlockNumber) -> bytes:
        number_to_hash_key = b'block-number-to-hash:%b-%d' % (wallet_address, block_number)
        return number_to_hash_key

    @staticmethod
    def make_transaction_hash_to_block_lookup_key(transaction_hash: Hash32) -> bytes:
        return b'transaction-hash-to-block:%s' % transaction_hash
    
    
    @staticmethod
    def make_current_head_root_lookup_key() -> bytes:
        return b'current-head-root'
    
    
    @staticmethod
    def make_historical_head_root_lookup_key() -> bytes:
        return b'historical-head-root-list'
    
    @staticmethod
    def make_head_root_for_timestamp_lookup_key(timestamp: int) -> bytes:
        #require that it is mod of 1000 seconds
        if timestamp % TIME_BETWEEN_HEAD_HASH_SAVE != 0:
            raise InvalidHeadRootTimestamp("Can only save or load head root hashes for timestamps in increments of {} seconds.".format(TIME_BETWEEN_HEAD_HASH_SAVE))
        return b'head-root-at-time:%i' % timestamp
    
    # @staticmethod
    # def make_block_hash_to_chain_wallet_address_lookup_key(block_hash: Hash32) -> bytes:
    #     return b'block-hash-to-chain-wallet-address:%b' % block_hash
    #
    @staticmethod
    def make_chronological_window_lookup_key(timestamp: int) -> bytes:
        #require that it is mod of 1000 seconds
        if timestamp % TIME_BETWEEN_HEAD_HASH_SAVE != 0:
            raise InvalidHeadRootTimestamp("Can only save or load chronological block for timestamps in increments of {} seconds.".format(TIME_BETWEEN_HEAD_HASH_SAVE))
        return b'chronological-block-window:%i' % timestamp
    
    @staticmethod
    def make_block_children_lookup_key(block_hash: Hash32) -> bytes:
        return b'block-children:%b' % block_hash
    
    @staticmethod
    def make_unprocessed_block_lookup_key(block_hash: Hash32) -> bytes:
        return b'is-unprocessed-block:%b' % block_hash
    
    @staticmethod
    def make_unprocessed_block_lookup_by_number_key(wallet_address:Address, block_number: BlockNumber) -> bytes:
        number_to_hash_key = b'block-number-to-unprocessed-hash:%b-%d' % (wallet_address, block_number)
        return number_to_hash_key
    
    @staticmethod
    def make_has_unprocessed_block_children_lookup_key(block_hash: Hash32) -> bytes:
        return b'has-unprocessed-block-children:%b' % block_hash
    
    @staticmethod
    def make_account_by_hash_lookup_key(account_hash: Hash32) -> bytes:
        return b'account-hash-lookup:%b' % account_hash
    
    @staticmethod
    def make_current_syncing_info_lookup_key() -> bytes:
        return b'current-syncing-info'
    
    @staticmethod
    def make_historical_minimum_gas_price_lookup_key() -> bytes:
        return b'h_minimum_gas_price'
    
    @staticmethod
    def make_historical_tx_per_centisecond_lookup_key() -> bytes:
        return b'h_tx_per_centisecond'
    
    @staticmethod
    def make_historical_network_tpc_capability_lookup_key() -> bytes:
        return b'h_net_tpc_cap'

    @staticmethod
    def make_peer_node_health_lookup(wallet_address:Address, after_block_number:BlockNumber) -> bytes:
        key = b'peer_node_health:%b-%d' % (wallet_address, after_block_number)
        return key

    @staticmethod
    def make_latest_reward_block_number_lookup(wallet_address: Address) -> bytes:
        key = b'latest_reward_block_number:%b' % (wallet_address)
        return key

    @staticmethod
    def make_latest_peer_node_health_timestamp_lookup_key() -> bytes:
        return b'latest_peer_node_health_timestamp'

    @staticmethod
    def make_reward_bundle_hash_lookup_key(reward_bundle_hash: Hash32) -> bytes:
        return b'reward_bundle_lookup:%b' % reward_bundle_hash

    @staticmethod
    def make_smart_contracts_with_pending_transactions_lookup_key() -> bytes:
        return b'smart_contracts_with_pending_lookup'
