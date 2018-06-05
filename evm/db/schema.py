from abc import ABCMeta, abstractmethod

from eth_typing import (
    BlockNumber,
    Hash32,
    Address,
)


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
    def make_block_number_to_hash_lookup_key(wallet_address:Address, block_number: BlockNumber) -> bytes:
        number_to_hash_key = b'block-number-to-hash:%b-%d' % (wallet_address, block_number)
        return number_to_hash_key

    @staticmethod
    def make_transaction_hash_to_block_lookup_key(transaction_hash: Hash32) -> bytes:
        return b'transaction-hash-to-block:%s' % transaction_hash
    
#    @staticmethod
#    def make_block_hash_to_state_root_lookup_key(block_hash: Hash32) -> bytes:
#        return b'block-hash-to-state-root:%s' % block_hash
#    
#    @staticmethod
#    def make_chronological_block_number_lookup_key(ch_block_number: ChBlockNumber) -> bytes:
#        return b'chronological_block_number:%d' % ch_block_number
#    
#    @staticmethod
#    def make_chronological_head_number_lookup_key() -> bytes:
#        return b'chronological_head_number' 
#    
#    @staticmethod
#    def make_block_hash_to_chronological_number_lookup_key(block_hash: Hash32) -> bytes:
#        return b'hash-to-chronological-block-number:%d' % block_hash
#    
#    @staticmethod
#    def make_last_imported_block_hash_lookup_key() -> bytes:
#        return b'last-imported-block'
    
    @staticmethod
    def make_current_state_root_lookup_key() -> bytes:
        return b'current-state-root'
    
    
    
    
    
    
