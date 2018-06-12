from abc import (
    ABCMeta,
    abstractmethod
)
from uuid import UUID
import logging
from lru import LRU
from typing import Set, Tuple  # noqa: F401

from eth_typing import Hash32

import rlp

from trie import (
    BinaryTrie,
    HexaryTrie,
)

from eth_hash.auto import keccak
from eth_utils import encode_hex

from trie.constants import (
    BLANK_HASH,
)

from evm.constants import (
    BLANK_ROOT_HASH,
    EMPTY_SHA3,
    SLASH_WALLET_ADDRESS,
    NUMBER_OF_HEAD_HASH_TO_SAVE,
    TIME_BETWEEN_HEAD_HASH_SAVE,
)
from evm.db.batch import (
    BatchDB,
)
from evm.db.cache import (
    CacheDB,
)
from evm.db.journal import (
    JournalDB,
)
from evm.rlp.accounts import (
    Account,
    TransactionKey,
)
from evm.validation import (
    validate_is_bytes,
    validate_uint256,
    validate_canonical_address,
)

from evm.utils.numeric import (
    int_to_big_endian,
)
from evm.utils.padding import (
    pad32,
)

from evm.db.schema import SchemaV1

from .hash_trie import HashTrie

from evm.rlp.sedes import(
    trie_root
)

# Use lru-dict instead of functools.lru_cache because the latter doesn't let us invalidate a single
# entry, so we'd have to invalidate the whole cache in _set_account() and that turns out to be too
# expensive.
account_cache = LRU(2048)

class ChainHeadDB():

    logger = logging.getLogger('evm.db.chain_head.ChainHeadDB')

    def __init__(self, db, root_hash=BLANK_HASH):
        """
        Binary trie database for storing the hash of the head block of each wallet address.
        """
        self.db = db
        self._batchtrie = BatchDB(db)
        self._trie = HashTrie(BinaryTrie(self._batchtrie, root_hash))
        self._trie_cache = CacheDB(self._trie)

    @property
    def root_hash(self):
        return self._trie.root_hash

    @root_hash.setter
    def root_hash(self, value):
        self._trie_cache.reset_cache()
        self._trie.root_hash = value
    
    def has_root(self, root_hash: bytes) -> bool:
        return root_hash in self._batchtrie

    
    #
    # Block hash API
    #
    def set_chain_head_hash(self, address, head_hash):
        validate_canonical_address(address, title="Wallet Address")
        validate_is_bytes(head_hash, title='Head Hash')
        self._trie_cache[address] = head_hash
        
    def get_chain_head_hash(self, address):
        validate_canonical_address(address, title="Wallet Address")
        head_hash = self._trie_cache.get(address)
        return head_hash
    
    #it is assumed that this is the head for a particular chain. because blocks can only be imported from the top.
    def add_block_hash_to_timestamp(self, address, head_hash, timestamp):
        validate_canonical_address(address, title="Wallet Address")
        validate_is_bytes(head_hash, title='Head Hash')
        validate_uint256(timestamp, title='timestamp')
        
        if self.check_if_root_hash_exists_at_timestamp(self.db, timestamp):
            #load a new copy of this db
            new_blockchain_head_db = ChainHeadDB.load_from_saved_root_hash_at_timestamp(self.db, timestamp)
            new_blockchain_head_db.set_chain_head_hash(address, head_hash)
            new_blockchain_head_db.persist()
            new_blockchain_head_db.save_current_root_hash_for_timestamp(timestamp)
    #
    # Record and discard API
    #
    def persist(self, save_current_root_hash = False) -> None:
        self._batchtrie.commit(apply_deletes=False)
        if save_current_root_hash:
            self.save_current_root_hash()
        
    
    #
    # Saving to database API
    #
    def save_current_root_hash(self) -> None:
        """
        Saves the current root_hash to the database to be loaded later
        """
        self.logger.debug("Saving current chain head root hash {}".format(self.root_hash))
        current_head_root_lookup_key = SchemaV1.make_current_head_root_lookup_key()
        
        self.db.set(
            current_head_root_lookup_key,
            self.root_hash,
        )
    
    @classmethod    
    def load_from_saved_root_hash(cls, db) -> Hash32:
        """
        Loads this class from the last saved root hash
        """

        current_head_root_lookup_key = SchemaV1.make_current_head_root_lookup_key()
        try:
            loaded_root_hash = db[current_head_root_lookup_key]
        except KeyError:
            #there is none. this must be a fresh genesis block type thing
            return cls(db) 
               
        return cls(db, loaded_root_hash)
    
    def save_current_root_hash_for_timestamp_if_not_exist(self, timestamp):
        if not self.check_if_root_hash_exists_at_timestamp(self.db, timestamp):
            self.save_current_root_hash_for_timestamp(timestamp)
            
    #timestamp must be in increments of 1000 seconds
    def save_current_root_hash_for_timestamp(self, timestamp):
        validate_uint256(timestamp, title='timestamp')
        self.logger.debug("Saving current head root at timestamp {}".format(timestamp))
        head_root_hash_lookup_key = SchemaV1.make_head_root_for_timestamp_lookup_key(timestamp)
        
        self.db.set(
            head_root_hash_lookup_key,
            self.root_hash,
        )
        
        #prune old ones
        timestamp_to_prune = timestamp - NUMBER_OF_HEAD_HASH_TO_SAVE*TIME_BETWEEN_HEAD_HASH_SAVE
        self.delete_root_hash_trie_for_timestamp(timestamp_to_prune)
       
    
    #prune old saved timestamps. only keeping last 1000
    def delete_root_hash_trie_for_timestamp(self, timestamp):
        if self.check_if_root_hash_exists_at_timestamp(self.db, timestamp):
            head_root_hash_lookup_key = SchemaV1.make_head_root_for_timestamp_lookup_key(timestamp)
            self.db.delete(head_root_hash_lookup_key)
            #dont want to delete the trie. that will delete the ones at future time too
        
    @classmethod
    def get_root_hash_saved_at_timestamp(cls, db, timestamp):
        validate_uint256(timestamp, title='timestamp')
        head_root_hash_lookup_key = SchemaV1.make_head_root_for_timestamp_lookup_key(timestamp)
        try:
            loaded_root_hash = db[head_root_hash_lookup_key]
        except KeyError:
            loaded_root_hash = BLANK_HASH
        return loaded_root_hash
    
    
    #timestamp must be in increments of 1000 seconds
    @classmethod
    def load_from_saved_root_hash_at_timestamp(cls, db, timestamp):
        loaded_root_hash = cls.get_root_hash_saved_at_timestamp(db, timestamp)
            
        return cls(db, loaded_root_hash)
    
    @classmethod
    def check_if_root_hash_exists_at_timestamp(cls, db, timestamp):
        validate_uint256(timestamp, title='timestamp')
        root_hash = cls.get_root_hash_saved_at_timestamp(db, timestamp)
        
        if root_hash == BLANK_HASH:
            return False
        else:
            return True
 
        
    
    
    
    