import time
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
    HexaryTrie,
)
from evm.db.trie import BinaryTrie
from trie.binary import parse_node
from trie.constants import (
    BLANK_HASH,
    KV_TYPE,
    BRANCH_TYPE,
    LEAF_TYPE,
    BYTE_0,
    BYTE_1,
)
from eth_hash.auto import keccak
from eth_utils import encode_hex


from evm.constants import (
    BLANK_ROOT_HASH,
    EMPTY_SHA3,
    SLASH_WALLET_ADDRESS,
    NUMBER_OF_HEAD_HASH_TO_SAVE,
    TIME_BETWEEN_HEAD_HASH_SAVE,
    ZERO_HASH32,
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
    validate_is_bytes_or_none,
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
    trie_root,
    hash32,
)

from rlp.sedes import (
    big_endian_int,
    CountableList,
    binary,
    List
)
from eth_utils import (
    int_to_big_endian,
    big_endian_to_int,
)
import itertools
import math
from evm.exceptions import (
    InvalidHeadRootTimestamp,        
)
from p2p.sedes import HashOrNone
from evm.utils.rlp import make_mutable

from sortedcontainers import SortedList

# Use lru-dict instead of functools.lru_cache because the latter doesn't let us invalidate a single
# entry, so we'd have to invalidate the whole cache in _set_account() and that turns out to be too
# expensive.
account_cache = LRU(2048)

class CurrentSyncingInfo(rlp.Serializable):
    fields = [
        ('timestamp', big_endian_int),
        ('head_root_hash', hash32),
        ('head_hash_of_last_chain', hash32),
    ]
    
    
class ChainHeadDB():

    logger = logging.getLogger('evm.db.chain_head.ChainHeadDB')

    def __init__(self, db, root_hash=BLANK_HASH):
        """
        Binary trie database for storing the hash of the head block of each wallet address.
        """
        self.db = db
        self._batchtrie = BatchDB(db)
        #self._trie = HashTrie(BinaryTrie(self._batchtrie, root_hash))
        self._trie = BinaryTrie(self._batchtrie, root_hash)
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
    # Trie Traversing
    #
#    def test(self):
#        
#        self._trie[b'1'] = b'adsfas'
#        self._trie[b'2'] = b'adsfasf'
#        self._trie[b'3'] = b'asdfasdf'
#        self._trie[b'4'] = b'sdfsfasdf'
#        self._trie[b'5'] = b'adsfasdfa'
#        self._trie[b'6'] = b'asdfasdf'
#        self.persist()
#        
#        
#        #root_node = self.db[self.root_hash]
#        leaf_nodes = self.get_head_block_hashes(self.root_hash)
##        next = False
##        for leaf in leaf_nodes:
##            if next == True:
##                print(leaf)
##                break
##            if leaf == b'asdfasdf':
##                next = True
##          
##        exit()
#        print(list(leaf_nodes))
#        
#        print(self.get_next_head_block_hash(self.root_hash, b'sdfsfasdf', reverse = False))
#        print(self.get_next_head_block_hash(self.root_hash, b'sdfsfasdf', reverse = True))
       
    def get_next_n_head_block_hashes(self, prev_head_hash = ZERO_HASH32, window_start = 0, window_length = 1, root_hash = None, reverse = False):
        """
        Gets the next head root hash in the leaves of the binary trie
        """
        if root_hash is None:
            root_hash = self.root_hash
        output_list = []
        next = False
        i = 0
        j = 0
        last = None
        for head_hash in self.get_head_block_hashes(root_hash, reverse = reverse):
              
            if next == True or (prev_head_hash == ZERO_HASH32 and window_start == 0):
                output_list.append(head_hash)
                i += 1
                if i >= window_length:
                    return output_list
                
            if head_hash == prev_head_hash or prev_head_hash == ZERO_HASH32:
                if prev_head_hash == ZERO_HASH32:
                    j += 1
                if j >= window_start:
                    next = True
                j += 1
            
            last = head_hash
            
        #if it gets here then we got to the last chain
        if len(output_list) < 1:
            output_list.append(last)
        return output_list
    
        #if this function returns less than window_length, then it is the end.
                
                
    def get_next_head_block_hash(self, prev_head_hash = ZERO_HASH32, root_hash = None, reverse = False):
        """
        Gets the next head root hash in the leaves of the binary trie
        """
        if root_hash is None:
            root_hash = self.root_hash
        next = False
        for head_hash in self.get_head_block_hashes(root_hash, reverse = reverse):
            if prev_head_hash == ZERO_HASH32 or next == True:
                return head_hash

            if head_hash == prev_head_hash:
                next = True
                
                  
    def get_head_block_hashes(self, root_hash = None, reverse = False):
        """
        Gets all of the head root hash leafs of the binary trie
        """
        if root_hash is None:
            root_hash = self.root_hash
        yield from self._trie.get_leaf_nodes(root_hash, reverse)
     
     
    #
    # Block hash API
    #
    def set_current_syncing_info(self, timestamp, head_root_hash, head_hash_of_last_chain = ZERO_HASH32):
        validate_is_bytes(head_root_hash, title='Head Root Hash')
        validate_is_bytes(head_hash_of_last_chain, title='Head Hash of last chain')
        validate_uint256(timestamp, title='timestamp')
        encoded = rlp.encode([timestamp, head_root_hash, head_hash_of_last_chain], sedes=CurrentSyncingInfo)
        self.db[SchemaV1.make_current_syncing_info_lookup_key()] = encoded
        
    def get_current_syncing_info(self):
        try:
            encoded = self.db[SchemaV1.make_current_syncing_info_lookup_key()]
            return rlp.decode(encoded, sedes=CurrentSyncingInfo)
        except KeyError:
            return None
        
    def set_current_syncing_last_chain(self, head_hash_of_last_chain):
        validate_is_bytes(head_hash_of_last_chain, title='Head Hash of last chain')
        syncing_info = self.get_current_syncing_info()
        new_syncing_info = syncing_info.copy(head_hash_of_last_chain = head_hash_of_last_chain)
        encoded = rlp.encode(new_syncing_info, sedes=CurrentSyncingInfo)
        self.db[SchemaV1.make_current_syncing_info_lookup_key()] = encoded
        
    def set_chain_head_hash(self, address, head_hash):
        validate_canonical_address(address, title="Wallet Address")
        validate_is_bytes(head_hash, title='Head Hash')
        self._trie_cache[address] = head_hash
        
        
    def get_chain_head_hash(self, address):
        validate_canonical_address(address, title="Wallet Address")
        head_hash = self._trie_cache.get(address)
        return head_hash
    
    def get_chain_head_hash_at_timestamp(self, address, timestamp):
        validate_canonical_address(address, title="Wallet Address")
        validate_uint256(timestamp, title='timestamp')
        #make sure it isnt in the future
        if timestamp > int(time.time()):
            raise InvalidHeadRootTimestamp()
        
        #first make sure the timestamp is correct.
        if timestamp % TIME_BETWEEN_HEAD_HASH_SAVE != 0:
            raise InvalidHeadRootTimestamp()
            
        historical_roots = self.get_historical_root_hashes()
        if historical_roots is None:
            return None
        
        if timestamp < historical_roots[0][0]:
            return None
        
        historical_roots_dict = dict(historical_roots)
        
        try:
            historical_root = historical_roots_dict[timestamp]
        except KeyError:
            historical_root = historical_roots[-1][1]
        
        new_chain_head_db = ChainHeadDB(self.db, historical_root)
        head_hash = new_chain_head_db._trie_cache.get(address)
        return head_hash
    
   
    #it is assumed that this is the head for a particular chain. because blocks can only be imported from the top.
    #this is going to be quite slow for older timestamps.
    def add_block_hash_to_timestamp(self, address, head_hash, timestamp):
        validate_canonical_address(address, title="Wallet Address")
        validate_is_bytes(head_hash, title='Head Hash')
        validate_uint256(timestamp, title='timestamp')
        
        #make sure it isnt in the future
        if timestamp > int(time.time()):
            raise InvalidHeadRootTimestamp()
        
        #first make sure the timestamp is correct.
        if timestamp % TIME_BETWEEN_HEAD_HASH_SAVE != 0:
            raise InvalidHeadRootTimestamp()
            
        #next we append the current state root to the end.
        self.append_current_root_hash_to_historical()
        
        #we cannot append to ones that are older than our database.
        #this also makes sure that we dont have to many historical entries
        start_timestamp = timestamp
        historical_roots = self.get_historical_root_hashes()
        if start_timestamp < historical_roots[0][0]:
            start_timestamp = historical_roots[0][0]
        

        last_finished_window = int(time.time()/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
        
        num_increments = int((last_finished_window - start_timestamp)/TIME_BETWEEN_HEAD_HASH_SAVE + 1)
        
        self.logger.debug("num_increments {}".format(num_increments))
        #only update up to current. do not update current. it is assumed that the current state is already updated
        
        #find starting index:
        starting_index = (timestamp - historical_roots[0][0])/TIME_BETWEEN_HEAD_HASH_SAVE
        
        for i in range(starting_index, num_increments):
            #load the hash, insert new head hash, persist with save as false
            root_hash_to_load = historical_roots[i][1]
            new_blockchain_head_db = ChainHeadDB(self.db, root_hash_to_load)
            new_blockchain_head_db.set_chain_head_hash(address, head_hash)
            new_blockchain_head_db.persist()
            new_root_hash = new_blockchain_head_db.root_hash
            historical_roots[i][1] = new_root_hash
            
        #now we finally save the new historical root hashes
        self.save_historical_root_hashes(historical_roots)
    

    #
    # Record and discard API
    #
    def persist(self, save_current_root_hash = False, save_root_hash_timestamps = True) -> None:
        self._batchtrie.commit(apply_deletes=False)
        if save_current_root_hash:
            self.save_current_root_hash(save_root_hash_timestamps)
        
    
    #
    # Saving to database API
    #
    def save_current_root_hash(self, save_root_hash_timestamps = True) -> None:
        """
        Saves the current root_hash to the database to be loaded later
        """
        self.logger.debug("Saving current chain head root hash {}".format(self.root_hash))
        current_head_root_lookup_key = SchemaV1.make_current_head_root_lookup_key()
        
        self.db.set(
            current_head_root_lookup_key,
            self.root_hash,
        )
        
        if save_root_hash_timestamps:
            self.append_current_root_hash_to_historical()
        

        
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
    

            

        
 
    #this has loops which are slow. but this should be rare to loop far. it will only happen if the node was offline for a long time. and it will only happen once
    def append_current_root_hash_to_historical(self):
        historical_roots = self.get_historical_root_hashes()
        last_finished_window = int(time.time()/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
        current_window = last_finished_window + TIME_BETWEEN_HEAD_HASH_SAVE
        if historical_roots is None:
            historical_roots = [[current_window, self.root_hash]]
            self.save_historical_root_hashes(historical_roots)
            return
        else:
            initial_first_time = historical_roots[0][0]
            latest_time = historical_roots[-1][0]
            #now we have to build all of the blocks between the previous one till now.
            if latest_time > last_finished_window:
                #we are on the current unfinished window already
                #simply update the last entry with the new hash
                historical_roots[-1][1] = self.root_hash
                self.save_historical_root_hashes(historical_roots)
                return
            
            elif latest_time < int(time.time()) - (NUMBER_OF_HEAD_HASH_TO_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE:
                #it is older than the ones we save. Just create the last NUMBER_OF_HEAD_HASH_TO_SAVE and set them all to the last saved one.
                new_historical_roots = []
                start_time = int(time.time()) - (NUMBER_OF_HEAD_HASH_TO_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
                for i in range(NUMBER_OF_HEAD_HASH_TO_SAVE):
                    new_historical_roots.append([start_time+TIME_BETWEEN_HEAD_HASH_SAVE*i,historical_roots[-1][1]])
                #dont forget to append the new one idiot
                new_historical_roots.append([current_window,self.root_hash])
                self.save_historical_root_hashes(new_historical_roots)
                final_first_time = new_historical_roots[0][0]
                
            else:
                num_increments_needed = int((last_finished_window - latest_time)/TIME_BETWEEN_HEAD_HASH_SAVE)
                for i in range(num_increments_needed):
                    historical_roots.append([latest_time+TIME_BETWEEN_HEAD_HASH_SAVE*(i+1), historical_roots[-1][1]])
                historical_roots.append([current_window,self.root_hash])
                
                #now trim it to the correct length. trim from the top
                del(historical_roots[:-1*NUMBER_OF_HEAD_HASH_TO_SAVE])
                self.save_historical_root_hashes(historical_roots)
                final_first_time = historical_roots[0][0]
            
            #need to delete chronological chain for any deleted things windows
            for i in range(initial_first_time, final_first_time, TIME_BETWEEN_HEAD_HASH_SAVE):
                self.delete_chronological_block_window(i)
                
#    def test(self):
#        data = [[1529097000, b'\xd7\x81\x12S\x06\xe7\xfd\xa3\xa9\xaf\x1aNR9\x16\xce\x82X\x95k6\x0b<\xed\xf7Ob\xbbya\x97\x17']]
#        #data = [b'\xd7\x81\x12S\x06\xe7\xfd\xa3\xa9\xaf\x1aNR9\x16\xce\x82X\x95k6\x0b<\xed\xf7Ob\xbbya\x97\x17']
#        #data = [1529097000]
#        #test = rlp.encode(data)
#        #print(test)
#        #print(rlp.decode(data, sedes=CountableList(big_endian_int, hash32)))
#        #print(rlp.encode(data, sedes=CountableList(big_endian_int)))
#        #print(rlp.encode(data, sedes=CountableList(hash32)))
#        encoded = rlp.encode(data, sedes=CountableList(List([big_endian_int, hash32])))
#        decoded = rlp.decode(encoded, sedes=CountableList(List([big_endian_int, hash32])))
#        print(make_mutable(decoded))
#        #print(big_endian_to_int(decoded[0][0]))
        
        
    #saved as [[timestamp, hash],[timestamp, hash]...]      
    def save_historical_root_hashes(self, root_hashes):
        historical_head_root_lookup_key = SchemaV1.make_historical_head_root_lookup_key()
        data = rlp.encode(root_hashes, sedes=CountableList(List([big_endian_int, hash32])))
        self.db.set(
            historical_head_root_lookup_key,
            data,
        )
        
         
    def get_historical_root_hashes(self, after_timestamp = None):
        historical_head_root_lookup_key = SchemaV1.make_historical_head_root_lookup_key()
        try:
            data = rlp.decode(self.db[historical_head_root_lookup_key], sedes=CountableList(List([big_endian_int, hash32])))
            if after_timestamp is None:
                return make_mutable(data)
            else:
                mutable = make_mutable(data)
                mutable_old_removed = list(mutable)
                num_deleted = 0
                for i in range(len(mutable)):
                    if mutable[i][0] < after_timestamp:
                        del(mutable_old_removed[i-num_deleted])
                        num_deleted += 1
                        
                if mutable_old_removed == []:
                    return None
                return mutable_old_removed
                
        except KeyError:
            return None
        
    def get_latest_timestamp(self):
        historical = self.get_historical_root_hashes()
        if historical is None:
            return 0
        latest_timestamp = historical[-1][0]
        return latest_timestamp
        
    
    #
    # Chronological chain
    #
    
    def add_block_hash_to_chronological_window(self, head_hash, timestamp):
        validate_is_bytes(head_hash, title='Head Hash')
        validate_uint256(timestamp, title='timestamp')
        
        #only add blocks for the proper time period        
        if timestamp > int(time.time()) - (NUMBER_OF_HEAD_HASH_TO_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE:
            #onlike the root hashes, this window is for the blocks added after the time
            window_for_this_block = int(timestamp/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
            
            data = self.load_chronological_block_window(window_for_this_block)
            #self.logger.debug("Saving chronological block window with old data {}".format(data)) 
            #now we simply add it.
            if data is None:
                new_data = [[timestamp, head_hash]]
                
            else:
                #most of the time we will be adding the timestamp near the end. so lets iterate backwards
                new_data = list(data)
                inserted = False
                for i in range(len(data)-1,-1,-1):
                    #self.logger.debug("debug {0}, {1}".format(big_endian_to_int(data[i][0]), timestamp))
                    if data[i][0] <= timestamp:
                        new_data.insert(i+1, [timestamp,head_hash])
                        inserted = True
                        break
                if not inserted:
                    new_data.insert(0, [timestamp,head_hash])
                    
            #self.logger.debug("Saving chronological block window with new data {}".format(new_data))    
            self.save_chronological_block_window(new_data, window_for_this_block)
    
    
    def save_chronological_block_window(self, data, timestamp):
        validate_uint256(timestamp, title='timestamp')
        if timestamp % TIME_BETWEEN_HEAD_HASH_SAVE != 0:
            raise InvalidHeadRootTimestamp("Can only save or load chronological block for timestamps in increments of {} seconds.".format(TIME_BETWEEN_HEAD_HASH_SAVE))
        
        chronological_window_lookup_key = SchemaV1.make_chronological_window_lookup_key(timestamp)
        encoded_data = rlp.encode(data,sedes=CountableList(List([big_endian_int, hash32])))
        self.db.set(
            chronological_window_lookup_key,
            encoded_data,
        )
    
    def load_chronological_block_window(self, timestamp):
        validate_uint256(timestamp, title='timestamp')
        if timestamp % TIME_BETWEEN_HEAD_HASH_SAVE != 0:
            raise InvalidHeadRootTimestamp("Can only save or load chronological block for timestamps in increments of {} seconds.".format(TIME_BETWEEN_HEAD_HASH_SAVE))
        
        chronological_window_lookup_key = SchemaV1.make_chronological_window_lookup_key(timestamp)
        try:
            data = rlp.decode(self.db[chronological_window_lookup_key], sedes=CountableList(List([big_endian_int, hash32])))
            return make_mutable(data)
        except KeyError:
            return None
        
    
    def delete_chronological_block_window(self, timestamp):
        validate_uint256(timestamp, title='timestamp')
        if timestamp % TIME_BETWEEN_HEAD_HASH_SAVE != 0:
            raise InvalidHeadRootTimestamp("Can only save or load chronological block for timestamps in increments of {} seconds.".format(TIME_BETWEEN_HEAD_HASH_SAVE))
        
        self.logger.debug("deleting chronological block window for timestamp {}".format(timestamp))
        chronological_window_lookup_key = SchemaV1.make_chronological_window_lookup_key(timestamp)
        try:
            del(self.db[chronological_window_lookup_key])
        except KeyError:
            pass
    
    
    

    
    
    
    