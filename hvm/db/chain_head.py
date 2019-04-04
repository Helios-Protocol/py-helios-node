import time
import asyncio
from functools import partial
from abc import (
    ABCMeta,
    abstractmethod
)
from uuid import UUID
import logging
from lru import LRU
from typing import (
    List,
    Union,
    Set,
    Tuple,
    Optional,
)

from eth_typing import Hash32, Address, BlockNumber

import rlp_cython as rlp
from hvm.utils.pickle import (
    hp_encode,
    hp_decode,
)


from hvm.utils.profile import profile

from trie import (
    HexaryTrie,
)
from hvm.db.trie import BinaryTrie
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


from hvm.constants import (
    BLANK_ROOT_HASH,
    EMPTY_SHA3,
    SLASH_WALLET_ADDRESS,
    NUMBER_OF_HEAD_HASH_TO_SAVE,
    TIME_BETWEEN_HEAD_HASH_SAVE,
    ZERO_HASH32,
)
from hvm.db.batch import (
    BatchDB,
)
from hvm.db.cache import (
    CacheDB,
)
from hvm.db.journal import (
    JournalDB,
)
from hvm.rlp.accounts import (
    Account,
    TransactionKey,
)

from hvm.utils.padding import de_sparse_timestamp_item_list

from hvm.types import Timestamp


from hvm.validation import (
    validate_is_bytes,
    validate_uint256,
    validate_canonical_address,
    validate_is_bytes_or_none,
    validate_historical_timestamp
)

from hvm.utils.numeric import (
    int_to_big_endian,
)
from hvm.utils.padding import (
    pad32,
)

from hvm.db.schema import SchemaV1

from .hash_trie import HashTrie

from hvm.rlp.sedes import(
    trie_root,
    hash32,
)

from rlp_cython.sedes import (
    big_endian_int,
    f_big_endian_int,
    binary,
)
from eth_utils import (
    int_to_big_endian,
    big_endian_to_int,
)
import itertools
import math
from hvm.exceptions import (
    InvalidHeadRootTimestamp,    
    JournalDbNotActivated,    
    AppendHistoricalRootHashTooOld,
)
from hvm.utils.rlp import make_mutable
import bisect
from sortedcontainers import SortedList
from sortedcontainers import SortedDict

# Use lru-dict instead of functools.lru_cache because the latter doesn't let us invalidate a single
# entry, so we'd have to invalidate the whole cache in _set_account() and that turns out to be too
# expensive.
account_cache = LRU(2048)

class CurrentSyncingInfo(rlp.Serializable):
    fields = [
        ('timestamp', big_endian_int),
        ('head_root_hash', hash32),
    ]
    

class ChainHeadDB():

    logger = logging.getLogger('hvm.db.chain_head.ChainHeadDB')
    
    _journaldb = None
    
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
        #self.logger.debug("reading root hash {}".format(encode_hex(self._trie.root_hash)))
        return self._trie.root_hash

    @root_hash.setter
    def root_hash(self, value):
        #self.logger.debug("setting root hash {}".format(encode_hex(value)))
        self._trie_cache.reset_cache()
        self._trie.root_hash = value
    
    def has_root(self, root_hash: bytes) -> bool:
        return root_hash in self._batchtrie

    def get_root_hash(self):
        return self.root_hash
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
        Gets the next head block hash in the leaves of the binary trie
        """
        
        validate_is_bytes(prev_head_hash, title='prev_head_hash')
        validate_uint256(window_start, title='window_start')
        validate_uint256(window_length, title='window_length')
         
        if root_hash is None:
            root_hash = self.root_hash
            
        validate_is_bytes(root_hash, title='Root Hash')
        
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
        Gets the next head block hash in the leaves of the binary trie
        """
        
        validate_is_bytes(prev_head_hash, title='prev_head_hash')
        
        if root_hash is None:
            root_hash = self.root_hash
        
        validate_is_bytes(root_hash, title='Root Hash')
        
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
        
        validate_is_bytes(root_hash, title='Root Hash')
        
        yield from self._trie.get_leaf_nodes(root_hash, reverse)

    def get_head_block_hashes_list(self, root_hash: Hash32=None, reverse: bool=False) -> List[Hash32]:
        return list(self.get_head_block_hashes(root_hash, reverse))

    def get_head_block_hashes_by_idx_list(self, idx_list: List[int], root_hash: Hash32=None) -> List[Hash32]:
        """
        Gets the head block hashes of the index range corresponding to the position of the leaves of the binary trie
        """

        if root_hash is None:
            root_hash = self.root_hash

        idx_set = set(idx_list)
        validate_is_bytes(root_hash, title='Root Hash')

        output_list = []

        for idx, head_hash in enumerate(self.get_head_block_hashes(root_hash)):
            if idx in idx_set:
                output_list.append(head_hash)
                idx_set.remove(idx)
            if len(idx_set) == 0:
                break


        return output_list

        # if this function returns less than window_length, then it is the end.
        
    
    #
    # Block hash API
    #
    def set_current_syncing_info(self, timestamp: Timestamp, head_root_hash: Hash32) -> None:
        validate_is_bytes(head_root_hash, title='Head Root Hash')
        validate_uint256(timestamp, title='timestamp')
        encoded = rlp.encode([timestamp, head_root_hash], sedes=CurrentSyncingInfo)
        self.db[SchemaV1.make_current_syncing_info_lookup_key()] = encoded
        
    def get_current_syncing_info(self) -> CurrentSyncingInfo:
        try:
            encoded = self.db[SchemaV1.make_current_syncing_info_lookup_key()]
            return rlp.decode(encoded, sedes=CurrentSyncingInfo)
        except KeyError:
            return None
        
    # def set_current_syncing_last_chain(self, head_hash_of_last_chain):
    #     validate_is_bytes(head_hash_of_last_chain, title='Head Hash of last chain')
    #     syncing_info = self.get_current_syncing_info()
    #     new_syncing_info = syncing_info.copy(head_hash_of_last_chain = head_hash_of_last_chain)
    #     encoded = rlp.encode(new_syncing_info, sedes=CurrentSyncingInfo)
    #     self.db[SchemaV1.make_current_syncing_info_lookup_key()] = encoded
        
    def set_chain_head_hash(self, address, head_hash):
        validate_canonical_address(address, title="Wallet Address")
        validate_is_bytes(head_hash, title='Head Hash')
        self._trie_cache[address] = head_hash
        
    def delete_chain_head_hash(self, address):
        validate_canonical_address(address, title="Wallet Address")
        try:
            del(self._trie_cache[address])
        except:
            pass
        
        
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
    
    def delete_chain(self, address, delete_from_historical_root_hashes:bool = True):
        validate_canonical_address(address, title="Wallet Address")
        self.delete_chain_head_hash(address)
        if delete_from_historical_root_hashes:
            self.add_block_hash_to_timestamp(address, BLANK_HASH, 0)
   
    #it is assumed that this is the head for a particular chain. because blocks can only be imported from the top.
    #this is going to be quite slow for older timestamps.
#    def add_block_hash_to_timestamp(self, address, head_hash, timestamp):
#        validate_canonical_address(address, title="Wallet Address")
#        validate_is_bytes(head_hash, title='Head Hash')
#        validate_uint256(timestamp, title='timestamp')
#        
#        currently_saving_window = int(time.time()/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE +TIME_BETWEEN_HEAD_HASH_SAVE
#        #make sure it isnt in the future
#        if timestamp > currently_saving_window:
#            raise InvalidHeadRootTimestamp()
#        
#        #first make sure the timestamp is correct.
#        if timestamp % TIME_BETWEEN_HEAD_HASH_SAVE != 0:
#            raise InvalidHeadRootTimestamp()
#            
#        #next we append the current state root to the end.
#        self.append_current_root_hash_to_historical()
#        
#        #we cannot append to ones that are older than our database.
#        #this also makes sure that we dont have to many historical entries
#        start_timestamp = timestamp
#        historical_roots = self.get_historical_root_hashes()
#        if start_timestamp < historical_roots[0][0]:
#            start_timestamp = historical_roots[0][0]
#        
#
#        #self.logger.debug("num_increments {}".format(num_increments))
#        #only update up to current. do not update current. it is assumed that the current state is already updated
#        
#        #find starting index:
#        starting_index = int((start_timestamp - historical_roots[0][0])/TIME_BETWEEN_HEAD_HASH_SAVE)
#
#        if starting_index < 0:
#            starting_index = 0
#        
#        #self.logger.debug("first:{} second:{}".format(starting_index, num_increments))
#        for i in range(starting_index, len(historical_roots)):
#            #load the hash, insert new head hash, persist with save as false
#            root_hash_to_load = historical_roots[i][1]
#            new_blockchain_head_db = ChainHeadDB(self.db, root_hash_to_load)
#            if head_hash == BLANK_HASH:
#                new_blockchain_head_db.delete_chain_head_hash(address)
#            else:
#                new_blockchain_head_db.set_chain_head_hash(address, head_hash)
#            new_blockchain_head_db.persist()
#            new_root_hash = new_blockchain_head_db.root_hash
#            historical_roots[i][1] = new_root_hash
#          
#        #now we finally save the new historical root hashes
#        self.save_historical_root_hashes(historical_roots)
    
    #going to need to optimize this with c code.
    #@profile(sortby='cumulative')
    def add_block_hash_to_timestamp(self, address, head_hash, timestamp):

        self.logger.debug("add_block_hash_to_timestamp")

        validate_canonical_address(address, title="Wallet Address")
        validate_is_bytes(head_hash, title='Head Hash')
        validate_uint256(timestamp, title='timestamp')


        currently_saving_window = int(time.time()/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE +TIME_BETWEEN_HEAD_HASH_SAVE
        #make sure it isnt in the future
        if timestamp > currently_saving_window:
            raise InvalidHeadRootTimestamp()
        
        
        #first make sure the timestamp is correct.
        if timestamp % TIME_BETWEEN_HEAD_HASH_SAVE != 0:
            raise InvalidHeadRootTimestamp()
        
        starting_timestamp, existing_root_hash = self.get_historical_root_hash(timestamp, return_timestamp = True)
        historical_roots = self.get_historical_root_hashes()

        if historical_roots is None:
            if head_hash == BLANK_HASH:
                self.delete_chain_head_hash(address)
            else:
                self.set_chain_head_hash(address, head_hash)
            self.persist()
            historical_roots = [[timestamp, self.root_hash]]
        else:

            if starting_timestamp is None:
                #this means there is no saved root hash that is at this time or before it. 
                #so we have no root hash to load
                self.logger.debug("Tried appending block hash to timestamp for time earlier than earliest timestamp. "
                                  "Adding to timestamp {}. ".format(timestamp))
            else:

                new_blockchain_head_db = ChainHeadDB(self.db, existing_root_hash)
                if head_hash == BLANK_HASH:
                    new_blockchain_head_db.delete_chain_head_hash(address)
                else:
                    new_blockchain_head_db.set_chain_head_hash(address, head_hash)
                new_blockchain_head_db.persist()
                new_root_hash = new_blockchain_head_db.root_hash

                if starting_timestamp == timestamp:
                    #we already had a root hash for this timestamp. just update the existing one.
                    #self.logger.debug("adding block hash to timestamp without propogating. root hash already existed. updating for time {}".format(timestamp))
                    historical_roots_dict = dict(historical_roots)
                    historical_roots_dict[timestamp] = new_root_hash
                    historical_roots = list(historical_roots_dict.items())
                    #self.logger.debug("finished adding block to timestamp. last_hist_root = {}, current_root_hash = {}".format(historical_roots[-1][1], self.root_hash))
                    #self.logger.debug(new_root_hash)
                else:
                    #self.logger.debug("adding block hash to timestamp without propogating. root hash didnt exist")
                    #sorted_historical_roots = SortedList(historical_roots)
                    historical_roots_dict = dict(historical_roots)
                    for loop_timestamp in range(starting_timestamp, timestamp, TIME_BETWEEN_HEAD_HASH_SAVE):
                        historical_roots_dict[loop_timestamp] = existing_root_hash

                    historical_roots_dict[timestamp] = new_root_hash
                    historical_roots = list(historical_roots_dict.items())
                
        #now propogate the new head hash to any saved historical root hashes newer than this one.
        #effeciently do this by starting from the end and working back. we can assume
        if historical_roots[-1][0] > timestamp:
            self.logger.debug("propogating historical root hash timestamps forward")
            for i in range(len(historical_roots)-1, -1, -1):
                if historical_roots[i][0] <= timestamp:
                    break
                
                root_hash_to_load = historical_roots[i][1]
                new_blockchain_head_db = ChainHeadDB(self.db, root_hash_to_load)
                if head_hash == BLANK_HASH:
                    new_blockchain_head_db.delete_chain_head_hash(address)
                else:
                    new_blockchain_head_db.set_chain_head_hash(address, head_hash)
                new_blockchain_head_db.persist()
                new_root_hash = new_blockchain_head_db.root_hash
                
                #have to do this in case it is a tuple and we cannot modify
                cur_timestamp = historical_roots[i][0]
                historical_roots[i] = [cur_timestamp,new_root_hash]
         
        #lets now make sure our root hash is the same as the last historical. It is possible that another thread or chain object
        #has imported a block since this one was initialized.

        self.save_historical_root_hashes(historical_roots)
        
        self.root_hash = historical_roots[-1][1]
        
    
    #
    # Record and discard API
    #

        
    def persist(self, save_current_root_hash = False, append_current_root_hash_to_historical = True) -> None:
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
        self.logger.debug("Saving current chain head root hash {}".format(encode_hex(self.root_hash)))
        current_head_root_lookup_key = SchemaV1.make_current_head_root_lookup_key()
        
        self.db.set(
            current_head_root_lookup_key,
            self.root_hash,
        )

        
    def get_saved_root_hash(self):
        current_head_root_lookup_key = SchemaV1.make_current_head_root_lookup_key()
        try:
            root_hash = self.db[current_head_root_lookup_key]
        except KeyError:
            # there is none. this must be a fresh genesis block type thing
            root_hash = BLANK_HASH

        return root_hash

    def load_saved_root_hash(self):
        current_head_root_lookup_key = SchemaV1.make_current_head_root_lookup_key()
        try:
            loaded_root_hash = self.db[current_head_root_lookup_key]
            self.root_hash = loaded_root_hash
        except KeyError:
            #there is none. this must be a fresh genesis block type thing
            pass
            
    @classmethod    
    def load_from_saved_root_hash(cls, db) -> 'ChainHeadDB':
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
        """
        Appends the current root hash to the list of historical root hashes that are in increments of TIME_BETWEEN_HEAD_HASH_SAVE
        it will also fill the gaps between times with whichever head root hash was previously.
        """
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
                start_time = last_finished_window - (NUMBER_OF_HEAD_HASH_TO_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
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
            if latest_time < final_first_time:
                delete_end = latest_time
            else:
                delete_end = final_first_time
                
            for i in range(initial_first_time, delete_end, TIME_BETWEEN_HEAD_HASH_SAVE):
                self.delete_chronological_block_window(i)
                

        
    def initialize_historical_root_hashes(self, root_hash: Hash32, timestamp: Timestamp) -> None:
        validate_is_bytes(root_hash, title='Head Hash')
        validate_historical_timestamp(timestamp, title="timestamp")

        #lets populate the root hash timestamp
        first_root_hash_timestamp = [[timestamp, root_hash]]
        self.save_historical_root_hashes(first_root_hash_timestamp)
    
    def save_single_historical_root_hash(self, root_hash, timestamp):
        validate_is_bytes(root_hash, title='Head Hash')
        validate_historical_timestamp(timestamp, title="timestamp")
        
        historical = self.get_historical_root_hashes()
        if historical is not None:
            historical = SortedList(historical)
            historical.add([timestamp, root_hash])
            historical = list(historical)
        else:
            historical = [[timestamp, root_hash]]
            
        self.save_historical_root_hashes(historical)
            
    
    def propogate_previous_historical_root_hash_to_timestamp(self, timestamp):
                
        validate_historical_timestamp(timestamp, title="timestamp")
        starting_timestamp, starting_root_hash = self.get_historical_root_hash(timestamp, return_timestamp = True)
        
        
                
        if starting_timestamp == None:
            raise AppendHistoricalRootHashTooOld("tried to propogate previous historical root hash, but there was no previous historical root hash")
        else:
            historical = SortedList(self.get_historical_root_hashes())
            
            if starting_timestamp == timestamp:
                #this means there is already a historical root hash for this time. Make sure it is correct. if not, delete it and all newer ones
                timestamp_for_previous_good_root_hash, previous_good_root_hash = self.get_historical_root_hash(timestamp-TIME_BETWEEN_HEAD_HASH_SAVE, return_timestamp = True)
                if starting_root_hash != previous_good_root_hash:
                    self.logger.debug("the existing historical root hash is incorrect. deleting this one and all future ones")
                    for timestamp_root_hash in reversed(historical.copy()):
                        if timestamp_root_hash[0] >= timestamp:
                            historical.pop()
                        
            for current_timestamp in range(starting_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE, timestamp+TIME_BETWEEN_HEAD_HASH_SAVE, TIME_BETWEEN_HEAD_HASH_SAVE):
                self.logger.debug("propogating previous root hash to time {}".format(current_timestamp))
                historical.add([current_timestamp, starting_root_hash])
            
            self.save_historical_root_hashes(list(historical))
            
            
            
        
    def get_last_complete_historical_root_hash(self):
        last_finished_window = int(time.time()/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
        historical = self.get_historical_root_hashes()
        if historical is None:
            return (None, None)
        
        historical_sorted = SortedDict(lambda x: int(x)*-1, historical)
            
        #this will iterate from largest time to smallest time
        for timestamp, root_hash in historical_sorted.items():
            if timestamp <= last_finished_window:
                return (timestamp, root_hash)
            
    def get_latest_historical_root_hash(self):
        historical = self.get_historical_root_hashes()
        if historical is None:
            return (None, None)
        historical_sorted = SortedDict(historical)
        return (historical_sorted.keys()[-1], historical_sorted.values()[-1])
            
#        for i in range(len(historical)-1, -1, -1):
#            if historical[i][0] <= last_finished_window:
#                return historical[i]
            
    #saved as [[timestamp, hash],[timestamp, hash]...]      
    def save_historical_root_hashes(self, root_hashes):
        #if root_hashes[-1][0] == 1534567000:
        #    exit()

        if len(root_hashes) > 1000:
            root_hashes = root_hashes[-1000:]

        historical_head_root_lookup_key = SchemaV1.make_historical_head_root_lookup_key()
        data = rlp.encode(root_hashes, sedes=rlp.sedes.FCountableList(rlp.sedes.FList([f_big_endian_int, hash32])))

        self.db.set(
            historical_head_root_lookup_key,
            data,
        )
        
    def get_historical_root_hash(self, timestamp: Timestamp, return_timestamp: bool = False) -> Tuple[Optional[Timestamp], Hash32]:
        '''
        This returns the historical root hash for a given timestamp.
        If no root hash exists for this timestamp, it will return the latest root hash prior to this timestamp
        '''
        validate_uint256(timestamp, title='timestamp')
        if timestamp % TIME_BETWEEN_HEAD_HASH_SAVE != 0:
            timestamp = int(timestamp/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
        historical = self.get_historical_root_hashes()

        root_hash_to_return = None
        timestamp_to_return = None

        #historical.sort()

        timestamps = [x[0] for x in historical]
        right_index = bisect.bisect_right(timestamps, timestamp)
        if right_index:
            index = right_index-1
            timestamp_to_return, root_hash_to_return = historical[index]

        if return_timestamp:
            return timestamp_to_return, root_hash_to_return
        else:
            return root_hash_to_return



    def get_historical_root_hashes(self, after_timestamp: Timestamp = None) -> Optional[List[List[Union[Timestamp, Hash32]]]]:
        '''
        This has been performance optimized December 22, 2018
        :param after_timestamp:
        :return:
        '''

        # Automatically sort when loading because we know the data will never be a mix of lists and tuples

        historical_head_root_lookup_key = SchemaV1.make_historical_head_root_lookup_key()
        try:
            data = rlp.decode(self.db[historical_head_root_lookup_key], sedes=rlp.sedes.FCountableList(rlp.sedes.FList([f_big_endian_int, hash32])), use_list=True)
            data.sort()
        except KeyError:
            return None

        if after_timestamp is None:
            to_return = data
        else:
            timestamps = [x[0] for x in data]
            index = bisect.bisect_left(timestamps, after_timestamp)
            to_return = data[index:]

        if len(to_return) == 0:
            return None


        return to_return



    def get_dense_historical_root_hashes(self, after_timestamp: Timestamp = None) -> Optional[List[List[Union[Timestamp, Hash32]]]]:
        '''
        Gets historical root hashes up the the present time with any gaps filled by propogating the previous root hash.
        :param after_timestamp:
        :return:
        '''

        last_finished_window = int(time.time() / TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
        current_window = last_finished_window + TIME_BETWEEN_HEAD_HASH_SAVE

        sparse_root_hashes = self.get_historical_root_hashes(after_timestamp = after_timestamp)
        if sparse_root_hashes is None:
            return None

        dense_root_hashes = de_sparse_timestamp_item_list(sparse_list = sparse_root_hashes,
                                                          spacing = TIME_BETWEEN_HEAD_HASH_SAVE,
                                                          end_timestamp = current_window)
        return dense_root_hashes

    def get_latest_timestamp(self):
        historical = self.get_historical_root_hashes()
        if historical is None:
            return 0

        latest_root_hash = historical[-1][1]
        latest_timestamp = historical[-1][0]
        # In most cases this should be the newest timestamp. But there might be cases where a root hash is propogated
        # forward but there havent been any new blocks. In this case, we just go back and find the earliest occurance
        # of this root hash. This should be rare so we don't have to worry about the for loop slowness.
        for i in range(len(historical)-1, -1, -1):
            if historical[-1][0] != latest_root_hash:
                break
            latest_root_hash = historical[i][1]
            latest_timestamp = historical[i][0]

        return latest_timestamp
        
    
    #
    # Chronological chain
    #
    
    def add_block_hash_to_chronological_window(self, head_hash, timestamp):
        validate_is_bytes(head_hash, title='Head Hash')
        validate_uint256(timestamp, title='timestamp')
        
        #only add blocks for the proper time period        
        if timestamp > int(time.time()) - (NUMBER_OF_HEAD_HASH_TO_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE:
            #unlike the root hashes, this window is for the blocks added after the time
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
    
    def delete_block_hash_from_chronological_window(self, head_hash, timestamp):
        validate_is_bytes(head_hash, title='Head Hash')
        validate_uint256(timestamp, title='timestamp')
        
        #only add blocks for the proper time period        
        if timestamp > int(time.time()) - (NUMBER_OF_HEAD_HASH_TO_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE:
            #onlike the root hashes, this window is for the blocks added after the time
            window_for_this_block = int(timestamp/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
            
            data = self.load_chronological_block_window(window_for_this_block)
            #self.logger.debug("Saving chronological block window with old data {}".format(data)) 
            #now we simply add it.
            if data is not None:
                #most of the time we will be adding the timestamp near the end. so lets iterate backwards
                try:
                    data.remove([timestamp,head_hash])
                except ValueError:
                    pass

            if data is not None:
                #self.logger.debug("Saving chronological block window with new data {}".format(new_data))    
                self.save_chronological_block_window(data, window_for_this_block)

            
            
    def save_chronological_block_window(self, data, timestamp):
        validate_uint256(timestamp, title='timestamp')
        if timestamp % TIME_BETWEEN_HEAD_HASH_SAVE != 0:
            raise InvalidHeadRootTimestamp("Can only save or load chronological block for timestamps in increments of {} seconds.".format(TIME_BETWEEN_HEAD_HASH_SAVE))
        
        chronological_window_lookup_key = SchemaV1.make_chronological_window_lookup_key(timestamp)
        encoded_data = rlp.encode(data,sedes=rlp.sedes.CountableList(rlp.sedes.List([f_big_endian_int, hash32])))
        self.db.set(
            chronological_window_lookup_key,
            encoded_data,
        )
    
    def load_chronological_block_window(self, timestamp: Timestamp) -> Optional[List[Union[int, Hash32]]]:
        validate_uint256(timestamp, title='timestamp')
        if timestamp % TIME_BETWEEN_HEAD_HASH_SAVE != 0:
            raise InvalidHeadRootTimestamp("Can only save or load chronological block for timestamps in increments of {} seconds.".format(TIME_BETWEEN_HEAD_HASH_SAVE))
        
        chronological_window_lookup_key = SchemaV1.make_chronological_window_lookup_key(timestamp)
        try:
            data = rlp.decode(self.db[chronological_window_lookup_key], sedes=rlp.sedes.CountableList(rlp.sedes.List([f_big_endian_int, hash32])), use_list = True)
            return data
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

