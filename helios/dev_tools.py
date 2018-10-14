import time
import random
import logging
import json

from hvm import MainnetChain
from hvm import constants
from hvm.chains.mainnet import (
    MAINNET_GENESIS_PARAMS,
    MAINNET_GENESIS_STATE,
    GENESIS_PRIVATE_KEY,
)

from hvm.db.backends.memory import MemoryDB
from hvm.db.journal import JournalDB
from hvm.db.chain import ChainDB
from hvm.rlp.transactions import BaseTransaction

from eth_utils import (
    encode_hex,
    decode_hex,        
)

from hp2p.kademlia import Address, Node

from hp2p.constants import LOCAL_PEER_POOL_PATH

from eth_hash.auto import keccak

from eth_keys import keys
from sys import exit

from trie import (
    HexaryTrie,
)

from hvm.db.hash_trie import HashTrie

from hvm.db.chain_head import ChainHeadDB

from hvm.constants import random_private_keys

logger = logging.getLogger("dev_tools_testing")

def create_new_genesis_params_and_state(private_key, total_supply = 100000000 * 10 ** 18, timestamp = int(time.time())):
    new_genesis_private_key = private_key

    print("Ceating new genesis params and state for genesis wallet address:")
    print(new_genesis_private_key.public_key.to_canonical_address())
    new_mainnet_genesis_params = {
        'parent_hash': constants.GENESIS_PARENT_HASH,
        'transaction_root': constants.BLANK_ROOT_HASH,
        'receive_transaction_root': constants.BLANK_ROOT_HASH,
        'receipt_root': constants.BLANK_ROOT_HASH,
        'bloom': 0,
        'block_number': constants.GENESIS_BLOCK_NUMBER,
        'gas_limit': constants.GENESIS_GAS_LIMIT,
        'gas_used': 0,
        'timestamp': timestamp,
        'extra_data': constants.GENESIS_EXTRA_DATA,
        'reward_hash': constants.GENESIS_REWARD_DATA,
        'account_balance': total_supply,
    }

    new_genesis_state = {
        new_genesis_private_key.public_key.to_canonical_address(): {
            "balance": total_supply,
            "code": b"",
            "nonce": 0,
            "storage": {}
        }
    }

    testdb1 = MemoryDB()
    genesis_header = MainnetChain.create_genesis_header(testdb1,
                                                        new_genesis_private_key.public_key.to_canonical_address(),
                                                        new_genesis_private_key, new_mainnet_genesis_params,
                                                        new_genesis_state)


    parameter_names = list(dict(genesis_header._meta.fields).keys())
    header_params = {}
    for parameter_name in parameter_names:
        header_params[parameter_name] = getattr(genesis_header, parameter_name)
    return header_params, new_genesis_state


def create_dev_test_random_blockchain_database(base_db):
   
    logger.debug("generating test blockchain db")
        
    #initialize db
    sender_chain = import_genesis_block(base_db)
    
    sender_chain.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price = 1, net_tpc_cap=5)
    
    order_of_chains = []
    #now lets add 100 send receive block combinations
    for i in range (5):
        random.shuffle(random_private_keys)
        if i == 0:
            privkey = GENESIS_PRIVATE_KEY
            receiver_privkey = keys.PrivateKey(random_private_keys[0])
        else:
            privkey = receiver_privkey
            receiver_privkey = keys.PrivateKey(random_private_keys[0])
        
        sender_chain = MainnetChain(base_db, privkey.public_key.to_canonical_address(), privkey)
        
        #add 3 send transactions to each block
        for j in range(2):
            sender_chain.create_and_sign_transaction_for_queue_block(
                    gas_price=0x01,
                    gas=0x0c3500,
                    to=receiver_privkey.public_key.to_canonical_address(),
                    value=100000000*10**18-i*1000000*10**18-random.randint(0,1000),
                    data=b"",
                    v=0,
                    r=0,
                    s=0
                    )
        
        imported_block = sender_chain.import_current_queue_block()
#        print("imported_block_hash = {}".format(encode_hex(imported_block.hash)))
#        receivable_tx = sender_chain.get_vm().state.account_db.get_receivable_transactions(receiver_privkey.public_key.to_canonical_address())
#        print('receivable_tx from account = {}'.format([encode_hex(x.sender_block_hash) for x in receivable_tx]))
#        exit()
        
        order_of_chains.append(encode_hex(privkey.public_key.to_canonical_address()))
        
        logger.debug("Receiving ")
        
        #then receive the transactions
        receiver_chain = MainnetChain(base_db, receiver_privkey.public_key.to_canonical_address(), receiver_privkey)
        receiver_chain.populate_queue_block_with_receive_tx()
        imported_block = receiver_chain.import_current_queue_block()
        
        imported_block_from_db = receiver_chain.chaindb.get_block_by_number(imported_block.header.block_number, receiver_chain.get_vm().get_block_class(),receiver_privkey.public_key.to_canonical_address())

        logger.debug("finished creating block group {}".format(i))
    
    order_of_chains.append(encode_hex(receiver_privkey.public_key.to_canonical_address()))
    
    #print("order_of_chains")
    #print(order_of_chains)
    #print(sender_chain.chain_head_db.get_historical_root_hashes())
    

#key_balance_dict = {priv_key: (balance, timestamp)}
def create_dev_fixed_blockchain_database(base_db, key_balance_dict):
    logger.debug("generating test fixed blockchain db")

    earliest_timestamp = int(time.time())
    required_total_supply = 0
    for balance_timestamp in key_balance_dict.values():
        required_total_supply += balance_timestamp[0]
        if balance_timestamp[1] < earliest_timestamp:
            earliest_timestamp = balance_timestamp[1]

    required_total_supply = required_total_supply*2

    #initialize db
    genesis_params, genesis_state = create_new_genesis_params_and_state(GENESIS_PRIVATE_KEY, required_total_supply, earliest_timestamp - 100000)
    sender_chain = MainnetChain.from_genesis(base_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), genesis_params, genesis_state)

    privkey = GENESIS_PRIVATE_KEY
    sender_chain = MainnetChain(base_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), privkey)


    prev_timestamp = 0
    for priv_key, balance_timestamp in key_balance_dict.items():
        dummy_sender_chain = MainnetChain(JournalDB(base_db), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), privkey)

        balance = balance_timestamp[0]
        timestamp = balance_timestamp[1]
        if timestamp < prev_timestamp:
            raise ValueError("timestamps must be in ascending order")

        receiver_privkey = priv_key

        dummy_sender_chain.create_and_sign_transaction_for_queue_block(
                gas_price=0x01,
                gas=0x0c3500,
                to=receiver_privkey.public_key.to_canonical_address(),
                value=balance,
                data=b"",
                v=0,
                r=0,
                s=0
                )

        # import the block into the dummy chain to complete it and make sure it is valid
        imported_block = dummy_sender_chain.import_current_queue_block()


        # altering block timestamp and importing again
        timestamp_modified_imported_block = imported_block.copy(header = imported_block.header.copy(timestamp = timestamp).get_signed(GENESIS_PRIVATE_KEY,dummy_sender_chain.network_id))
        sender_chain.import_block(timestamp_modified_imported_block, allow_unprocessed = False)

        logger.debug("Receiving ")

        #then receive the transactions
        receiver_chain = MainnetChain(base_db, receiver_privkey.public_key.to_canonical_address(), receiver_privkey)
        dummy_receiver_chain = MainnetChain(JournalDB(base_db), receiver_privkey.public_key.to_canonical_address(), receiver_privkey)
        dummy_receiver_chain.populate_queue_block_with_receive_tx()
        imported_block = dummy_receiver_chain.import_current_queue_block()

        # altering block timestamp and importing again
        timestamp_modified_imported_block = imported_block.copy(header=imported_block.header.copy(timestamp=timestamp).get_signed(receiver_privkey, dummy_receiver_chain.network_id))
        receiver_chain.import_block(timestamp_modified_imported_block, allow_unprocessed=False)

    logger.debug("finished creating fixed blockchain")
    

    
    



def import_genesis_block(base_db):
   
    logger.debug("importing genesis block")
        
    #initialize db
    return MainnetChain.from_genesis(base_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)
    #return MainnetChain.from_genesis(base_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY, MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)




def save_random_private_keys(limit):
    
    private_keys = []
    for i in range(limit):
        seed = bytes(random.randint(0,100000000))
        private_keys.append(keccak(seed))
            
    print(private_keys)
    
#save_random_private_keys(100) 
    
    
def load_peers_from_file():
    path = LOCAL_PEER_POOL_PATH
    #load existing pool
    with open(path, 'r') as peer_file:
        existing_peers_raw = peer_file.read()
        existing_peers = json.loads(existing_peers_raw)
    return existing_peers

def load_local_nodes(local_private_key = None):
    existing_peers = load_peers_from_file()
    peer_pool = []
    for i, peer in enumerate(existing_peers):
        if local_private_key is None or peer[0] != local_private_key.public_key.to_hex():
            peer_pool.append(Node(keys.PublicKey(decode_hex(peer[0])),Address(peer[1], peer[2], peer[3])))
    return peer_pool
        

    