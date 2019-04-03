import time
import random
import logging
import json

from typing import List

from hvm import MainnetChain
from hvm import constants
from hvm.chains.mainnet import (
    MAINNET_GENESIS_PARAMS,
    MAINNET_GENESIS_STATE,
    GENESIS_PRIVATE_KEY,
)

from hvm.db.backends.memory import MemoryDB
from hvm.db.backends.level import LevelDB
from hvm.db.journal import JournalDB
from hvm.rlp.blocks import BaseQueueBlock
from hvm.rlp.consensus import NodeStakingScore
from hvm.rlp.transactions import BaseTransaction

from eth_utils import (
    encode_hex,
    decode_hex,        
)

from hp2p.kademlia import Address, Node


from eth_hash.auto import keccak

from eth_keys import keys
from sys import exit

from trie import (
    HexaryTrie,
)

from helios.rpc.format import block_to_dict
from hvm.db.hash_trie import HashTrie

from hvm.db.chain_head import ChainHeadDB

from hvm.constants import random_private_keys, GAS_TX, MIN_TIME_BETWEEN_BLOCKS, MIN_ALLOWED_TIME_BETWEEN_REWARD_BLOCKS, \
    TIME_BETWEEN_HEAD_HASH_SAVE
from hvm.vm.forks.helios_testnet import HeliosTestnetQueueBlock

logger = logging.getLogger("dev_tools_testing")





def create_new_genesis_params_and_state(private_key, total_supply = 100000000 * 10 ** 18, timestamp = int(time.time())):
    print("CREATING GENESIS BLOCK WITH TOTAL SUPPLY = ", total_supply)
    new_genesis_private_key = private_key

    print("Ceating new genesis params and state for genesis wallet address:")
    print(new_genesis_private_key.public_key.to_canonical_address())
    new_mainnet_genesis_params = {
        'chain_address': new_genesis_private_key.public_key.to_canonical_address(),
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
        'reward_hash': constants.GENESIS_REWARD_HASH,
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


def print_blockchain_database(base_db):
    node_1 = MainnetChain(base_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    chain_head_hashes = node_1.chain_head_db.get_head_block_hashes_list()

    i = 0
    for head_hash in chain_head_hashes:
        print("Chain number {}".format(i))
        chain = node_1.get_all_blocks_on_chain_by_head_block_hash(head_hash)

        j = 0
        for block in chain:
            print("Block number {}".format(i))
            print(block_to_dict(block, True, node_1))
            j += 1
        i += 1





def create_dev_test_random_blockchain_db_with_reward_blocks(base_db = None, num_iterations = 5):
    # initialize db
    if base_db == None:
        base_db = MemoryDB()


    create_dev_test_random_blockchain_database(base_db, timestamp = 'genesis')

    node_1 = MainnetChain(base_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

    chain_head_hashes = node_1.chain_head_db.get_head_block_hashes_list()

    last_block_timestamp = 0
    for head_hash in chain_head_hashes:
        header = node_1.chaindb.get_block_header_by_hash(head_hash)
        if header.timestamp > last_block_timestamp:
            last_block_timestamp = header.timestamp

    private_keys_dict = {}
    for random_private_key in random_private_keys:
        priv_key = keys.PrivateKey(random_private_key)
        private_keys_dict[priv_key.public_key.to_address()] = priv_key

    private_keys_dict[GENESIS_PRIVATE_KEY.public_key.to_address()] = GENESIS_PRIVATE_KEY

    for i in range(num_iterations):
        random_int = random.randint(0,len(private_keys_dict)-1)
        if i == 0:
            privkey = GENESIS_PRIVATE_KEY
            receiver_privkey = private_keys_dict[list(private_keys_dict.keys())[random_int]]
        else:
            privkey = receiver_privkey
            receiver_privkey = private_keys_dict[list(private_keys_dict.keys())[random_int]]

        tx_timestamp = last_block_timestamp + MIN_TIME_BETWEEN_BLOCKS+2
        tx_list = [[privkey, receiver_privkey, 10000000*10**18-i*100000*10**18-random.randint(0,1000), tx_timestamp]]


        add_transactions_to_blockchain_db(base_db, tx_list)

        node_1 = MainnetChain(base_db, privkey.public_key.to_canonical_address(), privkey)

        chain_head_hashes = node_1.chain_head_db.get_head_block_hashes_list()

        reward_block_time = tx_timestamp + MIN_ALLOWED_TIME_BETWEEN_REWARD_BLOCKS+MIN_TIME_BETWEEN_BLOCKS+2

        node_staking_scores = []
        for head_hash in chain_head_hashes:
            address = node_1.chaindb.get_chain_wallet_address_for_block_hash(head_hash)
            if not (address == privkey.public_key.to_canonical_address()):
                after_block_number = node_1.chaindb.get_latest_reward_block_number(privkey.public_key.to_canonical_address())

                node_staking_score = NodeStakingScore(privkey.public_key.to_canonical_address(),
                                                      1,
                                                      after_block_number,
                                                      reward_block_time,
                                                      head_hash,
                                                      v=0,
                                                      r=0,
                                                      s=0)

                signed_node_staking_score = node_staking_score.get_signed(private_keys_dict[encode_hex(address)], node_1.network_id)

                node_staking_scores.append(signed_node_staking_score)


        reward_bundle = node_1.consensus_db.create_reward_bundle_for_block(privkey.public_key.to_canonical_address(),
                                                               node_staking_scores,
                                                               reward_block_time)


        valid_block = create_valid_block_at_timestamp(base_db, privkey, reward_bundle = reward_bundle, timestamp = reward_block_time)

        assert(valid_block.header.timestamp == reward_block_time)
        node_1.import_block(valid_block)
        last_block_timestamp = reward_block_time


    return base_db


def create_valid_block_at_timestamp(base_db, private_key, transactions = None, receive_transactions = None, reward_bundle = None, timestamp = None):
    '''
    Tries to create a valid block based in the invalid block. The transactions and reward bundle must already be valid
    :param base_db:
    :param private_key:
    :param invalid_block:
    :return:
    '''
    if timestamp == None:
        timestamp = int(time.time())

    chain = MainnetChain(JournalDB(base_db), private_key.public_key.to_canonical_address(), private_key)

    queue_block = chain.get_queue_block()
    queue_block = queue_block.copy(transactions=transactions,
                                   receive_transactions=receive_transactions,
                                   reward_bundle=reward_bundle)


    valid_block = chain.get_vm().import_block(queue_block, timestamp = timestamp, validate = False)


    return valid_block


def create_dev_test_random_blockchain_database(base_db = None, num_iterations = None, timestamp = None):
    logger.debug("generating test blockchain db")
    if base_db == None:
        base_db = MemoryDB()

    if num_iterations == None:
        num_iterations = 5

    #initialize db
    sender_chain = import_genesis_block(base_db)
    # sender_chain.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price = 1, net_tpc_cap=5)\

    if timestamp == None:
        timestamp = int(time.time()) - num_iterations*MIN_TIME_BETWEEN_BLOCKS
    elif timestamp == "genesis":
        timestamp = MAINNET_GENESIS_PARAMS['timestamp'] + TIME_BETWEEN_HEAD_HASH_SAVE

    tx_list = []
    for i in range (num_iterations):
        random.shuffle(random_private_keys)
        if i == 0:
            privkey = GENESIS_PRIVATE_KEY
            receiver_privkey = keys.PrivateKey(random_private_keys[0])
        else:
            privkey = receiver_privkey
            receiver_privkey = keys.PrivateKey(random_private_keys[0])

        tx_timestamp = timestamp+i*MIN_TIME_BETWEEN_BLOCKS
        tx_list.append([privkey, receiver_privkey, 10000000 * 10 ** 18 - i * 100000 * 10 ** 18 - random.randint(0, 1000), tx_timestamp])


    add_transactions_to_blockchain_db(base_db, tx_list)

    return base_db


def add_transactions_to_blockchain_db(base_db, tx_list: List):
    # sort by time
    tx_list.sort(key=lambda x: x[3])

    for tx_key in tx_list:
        sender_priv_key = tx_key[0]
        receive_priv_key = tx_key[1]
        amount = tx_key[2]
        tx_timestamp = int(tx_key[3])

        if len(tx_key) > 4:
            gas_price = tx_key[4]
        else:
            gas_price = 1

        total_gas = gas_price
        sender_chain = MainnetChain(base_db, sender_priv_key.public_key.to_canonical_address(), sender_priv_key)
        dummy_sender_chain = MainnetChain(JournalDB(base_db), sender_priv_key.public_key.to_canonical_address(),
                                          sender_priv_key)

        dummy_sender_chain.create_and_sign_transaction_for_queue_block(
            gas_price=gas_price,
            gas=GAS_TX*gas_price,
            to=receive_priv_key.public_key.to_canonical_address(),
            value=amount,
            data=b"",
            v=0,
            r=0,
            s=0
        )

        # import the block into the dummy chain to complete it and make sure it is valid
        imported_block = dummy_sender_chain.import_current_queue_block()

        # altering block timestamp and importing again
        timestamp_modified_imported_block = imported_block.copy(
            header=imported_block.header.copy(timestamp=tx_timestamp).get_signed(sender_priv_key,
                                                                                 dummy_sender_chain.network_id))
        sender_chain.import_block(timestamp_modified_imported_block, allow_unprocessed=False)

        # then receive the transactions
        receiver_chain = MainnetChain(base_db, receive_priv_key.public_key.to_canonical_address(), receive_priv_key)
        dummy_receiver_chain = MainnetChain(JournalDB(base_db), receive_priv_key.public_key.to_canonical_address(),
                                            receive_priv_key)
        dummy_receiver_chain.populate_queue_block_with_receive_tx()
        imported_block = dummy_receiver_chain.import_current_queue_block()

        # altering block timestamp and importing again
        timestamp_modified_imported_block = imported_block.copy(
            header=imported_block.header.copy(timestamp=tx_timestamp).get_signed(receive_priv_key,
                                                                                 dummy_receiver_chain.network_id))
        receiver_chain.import_block(timestamp_modified_imported_block, allow_unprocessed=False)


#tx_list = [from priv_key, to priv_key, amount, timestamp]
def create_dev_test_blockchain_database_with_given_transactions(base_db, tx_list: List, use_real_genesis = False):

    # sort by time
    tx_list.sort(key=lambda x: x[3])

    genesis_chain_stake = 100000000000000000

    earliest_timestamp = tx_list[0][3]
    required_total_supply = sum([x[2]+GAS_TX for x in tx_list if x[0] == GENESIS_PRIVATE_KEY])+genesis_chain_stake

    if use_real_genesis:
        import_genesis_block(base_db)
    else:
        genesis_params, genesis_state = create_new_genesis_params_and_state(GENESIS_PRIVATE_KEY, required_total_supply, earliest_timestamp - 100000)

        # import genesis block
        MainnetChain.from_genesis(base_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), genesis_params, genesis_state)

    add_transactions_to_blockchain_db(base_db, tx_list)



#key_balance_dict = {priv_key: (balance, timestamp)}
def create_dev_fixed_blockchain_database(base_db, key_balance_dict, use_real_genesis = False):
    logger.debug("generating test fixed blockchain db")

    earliest_timestamp = int(time.time())
    required_total_supply = 0
    for balance_timestamp in key_balance_dict.values():
        required_total_supply += balance_timestamp[0]
        if balance_timestamp[1] < earliest_timestamp:
            earliest_timestamp = balance_timestamp[1]

    required_total_supply = required_total_supply*2

    #initialize db
    if use_real_genesis:
        sender_chain = import_genesis_block(base_db)
    else:
        genesis_params, genesis_state = create_new_genesis_params_and_state(GENESIS_PRIVATE_KEY, required_total_supply, earliest_timestamp - 100000)
        sender_chain = MainnetChain.from_genesis(base_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), genesis_params, genesis_state)

    sender_chain.chaindb.initialize_historical_minimum_gas_price_at_genesis(min_gas_price=1, net_tpc_cap=5)

    prev_timestamp = 0
    for priv_key, balance_timestamp in key_balance_dict.items():
        sender_chain = MainnetChain(base_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)
        dummy_sender_chain = MainnetChain(JournalDB(base_db), GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)

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

        #logger.debug("Receiving ")

        #then receive the transactions
        receiver_chain = MainnetChain(base_db, receiver_privkey.public_key.to_canonical_address(), receiver_privkey)
        dummy_receiver_chain = MainnetChain(JournalDB(base_db), receiver_privkey.public_key.to_canonical_address(), receiver_privkey)
        dummy_receiver_chain.populate_queue_block_with_receive_tx()
        imported_block = dummy_receiver_chain.import_current_queue_block()

        # altering block timestamp and importing again
        timestamp_modified_imported_block = imported_block.copy(header=imported_block.header.copy(timestamp=timestamp).get_signed(receiver_privkey, dummy_receiver_chain.network_id))
        receiver_chain.import_block(timestamp_modified_imported_block, allow_unprocessed=False)


    logger.debug("finished creating fixed blockchain")

    # sender_chain = MainnetChain(base_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), privkey)
    # latest_historical_timestamp = sender_chain.chain_head_db.get_historical_root_hashes()[-1][0]
    # chronological_block_window = sender_chain.chain_head_db.load_chronological_block_window(latest_historical_timestamp)
    # print("AAAAAAAAAAAA")
    # print(latest_historical_timestamp)
    # print(chronological_block_window)

    
    



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
    
    
def load_peers_from_file(path):
    #load existing pool
    with path.open('r') as peer_file:
        existing_peers_raw = peer_file.read()
        existing_peers = json.loads(existing_peers_raw)
    return existing_peers

def load_local_nodes(path, local_private_key = None):
    existing_peers = load_peers_from_file(path)
    peer_pool = []
    for i, peer in enumerate(existing_peers):
        if local_private_key is None or peer[0] != local_private_key.public_key.to_hex():
            peer_pool.append(Node(keys.PublicKey(decode_hex(peer[0])),Address(peer[1], peer[2], peer[3])))
    return peer_pool
        


def create_predefined_blockchain_database(db, genesis_block_timestamp = None, instance = 0):
    if genesis_block_timestamp is None:
        genesis_block_timestamp = MAINNET_GENESIS_PARAMS['timestamp']

    from hvm.constants import MIN_TIME_BETWEEN_BLOCKS, TIME_BETWEEN_HEAD_HASH_SAVE

    private_keys = []
    for i in range(11):
        private_keys.append(keys.PrivateKey(random_private_keys[i]))

    if instance == 0:
        key_balance_dict = {
            private_keys[0]: (10000000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS),
            private_keys[1]: (2000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*2),
            private_keys[2]: (3400*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*3),
            private_keys[3]: (1000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*4),
            private_keys[4]: (14000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*5),
            private_keys[5]: (2400*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*6),
            private_keys[6]: (100000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS),
            private_keys[7]: (40000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*8),
            private_keys[8]: (10000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*9),
            private_keys[9]: (1000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*10),

        }
    elif instance == 1:
        key_balance_dict = {
            private_keys[0]: (10000000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS),
            private_keys[1]: (2000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*2),
            private_keys[2]: (3400*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*3),
            private_keys[3]: (1000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*4),
            private_keys[4]: (14000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*5),
            private_keys[5]: (2400*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*6),
            private_keys[6]: (100000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS),
            private_keys[7]: (40000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*8),
            private_keys[8]: (10000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*9),
            private_keys[9]: (1000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*10),
            private_keys[10]: (1000 * 10 ** 18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS * 10),

        }

    elif instance == 2:
        key_balance_dict = {
            private_keys[0]: (10000000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS),
            private_keys[1]: (2000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*2),
            private_keys[2]: (3400*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*3),
            private_keys[3]: (1000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*4),
            private_keys[4]: (14000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*5),
            private_keys[5]: (2400*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*6),
            private_keys[6]: (100000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS),
            private_keys[7]: (40000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*8),
            private_keys[8]: (10000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*9),
            private_keys[9]: (1000*10**18, genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE + MIN_TIME_BETWEEN_BLOCKS*10),
        }
    if genesis_block_timestamp == MAINNET_GENESIS_PARAMS['timestamp']:
        create_dev_fixed_blockchain_database(db, key_balance_dict, True)
    else:
        create_dev_fixed_blockchain_database(db, key_balance_dict)



def create_blockchain_database_for_exceeding_tpc_cap(base_db, tpc_cap_to_exceed=5, num_tpc_windows_to_go_back=200, use_real_genesis = False):

    from hvm.constants import MIN_TIME_BETWEEN_BLOCKS, TIME_BETWEEN_HEAD_HASH_SAVE

    genesis_block_timestamp = int(time.time()/100)*100 - num_tpc_windows_to_go_back*100

    private_keys = []
    for i in range(len(random_private_keys)):
        private_keys.append(keys.PrivateKey(random_private_keys[i]))

    tx_list = []

    start = genesis_block_timestamp+100+MIN_TIME_BETWEEN_BLOCKS
    end = int(time.time()/100)*100+100
    for centisecond_window_timestamp in range(start, end, 100):
        for j in range(tpc_cap_to_exceed):
            random.shuffle(private_keys)
            sender = GENESIS_PRIVATE_KEY
            receiver = private_keys[0]
            amount = 1000
            timestamp = centisecond_window_timestamp+j*MIN_TIME_BETWEEN_BLOCKS

            tx_list.append([sender,receiver,amount,timestamp])

    assert(len(tx_list) == tpc_cap_to_exceed*num_tpc_windows_to_go_back)

    #print(tx_list)
    create_dev_test_blockchain_database_with_given_transactions(base_db, tx_list, use_real_genesis)


def create_random_blockchain_database_to_time(base_db, start_time, end_time, tx_per_1000_seconds=1, use_real_genesis = False):

    from hvm.constants import MIN_TIME_BETWEEN_BLOCKS, TIME_BETWEEN_HEAD_HASH_SAVE

    genesis_block_timestamp = int(start_time/100)*100

    private_keys = []
    for i in range(len(random_private_keys)):
        private_keys.append(keys.PrivateKey(random_private_keys[i]))

    tx_list = []

    start = genesis_block_timestamp+1000+MIN_TIME_BETWEEN_BLOCKS
    end = int(end_time/1000)*1000+1000
    for window_timestamp in range(start, end, 1000):
        for j in range(tx_per_1000_seconds):
            random.shuffle(private_keys)
            sender = GENESIS_PRIVATE_KEY
            receiver = private_keys[0]
            amount = 1000
            timestamp = window_timestamp+j*MIN_TIME_BETWEEN_BLOCKS

            tx_list.append([sender,receiver,amount,timestamp])


    #print(tx_list)
    create_dev_test_blockchain_database_with_given_transactions(base_db, tx_list, use_real_genesis)

def add_random_transactions_to_db_for_time_window(base_db, start_time, end_time, tx_per_1000_seconds=1):

    from hvm.constants import MIN_TIME_BETWEEN_BLOCKS, TIME_BETWEEN_HEAD_HASH_SAVE

    genesis_block_timestamp = int(start_time / 100) * 100

    private_keys = []
    for i in range(len(random_private_keys)):
        private_keys.append(keys.PrivateKey(random_private_keys[i]))

    tx_list = []

    start = genesis_block_timestamp + 1000 + MIN_TIME_BETWEEN_BLOCKS
    end = int(end_time / 1000) * 1000 + 1000
    for window_timestamp in range(start, end, 1000):
        for j in range(tx_per_1000_seconds):
            random.shuffle(private_keys)
            sender = GENESIS_PRIVATE_KEY
            receiver = private_keys[0]
            amount = 1000
            timestamp = window_timestamp + j * MIN_TIME_BETWEEN_BLOCKS

            tx_list.append([sender, receiver, amount, timestamp])

    add_transactions_to_blockchain_db(base_db, tx_list)

