import time
import random
import logging
import json

from evm import MainnetChain
from evm.chains.mainnet import (
    MAINNET_GENESIS_HEADER,
    MAINNET_GENESIS_PARAMS,
    MAINNET_GENESIS_STATE,
    GENESIS_PRIVATE_KEY,
)

from evm.db.backends.level import LevelDB
from evm.db.chain import ChainDB
from evm.rlp.transactions import BaseTransaction

from eth_utils import (
    encode_hex,
    decode_hex,        
)

from p2p.kademlia import Address, Node

from p2p.constants import LOCAL_PEER_POOL_PATH

from eth_hash.auto import keccak

from eth_keys import keys
from sys import exit

from trie import (
    HexaryTrie,
)

from evm.db.hash_trie import HashTrie

from evm.db.chain_head import ChainHeadDB

logger = logging.getLogger("dev_tools_testing")

random_private_keys = [b'\xd3.MQ\x1f\xb2SMN\x9c\xea\xc5\x05t#\xca! Da\xd3"\x0f[\x00xr\xf4Z>ui', b'Y\xd8\x16TO\x11\x18\x10~$\x13\xf9\xb4 W\xaa\xd6y\xeb\x1b\x1a\xd3\x8aRd\xbc6\xbeG\xecNi', b']\xaal\x02d\x12\x86\xe9Yg\x84]\x0fD]6\xa7\t\xe7\xf9\xa0\x13X\x94\xc2\x82q\xdd\xae\x9a\x9a\xa9', b']\xa9V??=\xc7*\\x\xbbaS\x9c\x89\xc9\t\x98\x16X\x8a>\x1a\xb9"\xfb\xec\xa0%\x12\xa3Z', b'\x94;\x18\xe4\xa8\xc2,\xc7\xfe\xec:\x82\x8f\x08\xec\xdf7\xb6\xcff\xd7\x04\xf4\xbaF>\xf4\xaf\xbd\x96\xeb\x95', b"\x83YXg\xbf\x95\xb5\x1c\xd7\x96&w;\xe8L\x0cw\xe1,b7\x92!f\xe8\xa6'\x11_n\xa6/", b'\x9f\x99\x01T\xd9\xbb\xb0\xdby}\xeeR\x8d[\xb5wm\xa4k+\x9bi\x8a\x11\xec\xc3Y\xb6\xdf\xc9\xe5\x1e', b'y\xd0\x98:\x0c\xb9\xe5`\xf93.?],\xd3[\x08\xca\xd5\xc9$\xda\xa3\x89\xbf\xebj\x8b\xcc\xff\xd2\x04', b'\xea7\xc9\xb3\x95\xfdP#R\xab\xa6\x18$\xab\xabsN\xe0\x97\xd2ka\xa4\xa9@\xb1\xbd\xd5\xeb\xd4\xfa\x94', b'\x8ck?\xba>\xae\xbf\xd6\xf2\xecKe\x81${>\xd2\x90P\x1b\xd8\x9a\x95\x1e\xcf\x1f\r\x1c x\x86\xa5']

def create_dev_test_random_blockchain_database(base_db):
   
    logger.debug("generating test blockchain db")
        
    #initialize db
    sender_chain = MainnetChain.from_genesis(base_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY, MAINNET_GENESIS_PARAMS, MAINNET_GENESIS_STATE)
    
    #now lets add 100 send receive block combinations
    for i in range (10):
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
                    value=10000000000000000-i*800000,
                    data=b"",
                    v=0,
                    r=0,
                    s=0
                    )
        
        sender_chain.import_current_queue_block()
        
        logger.debug("Receiving ")
        
        #then receive the transactions
        receiver_chain = MainnetChain(base_db, receiver_privkey.public_key.to_canonical_address(), receiver_privkey)
        receiver_chain.populate_queue_block_with_receive_tx()
        receiver_chain.import_current_queue_block()
        
        logger.debug("finished creating block group {}".format(i))
    
    
    
    
    
    
    
    
def save_random_private_keys(limit):
    
    private_keys = []
    for i in range(limit):
        seed = bytes(random.randint(0,100000000))
        private_keys.append(keccak(seed))
            
    print(private_keys)
    
#save_random_private_keys(10) 
    
    
def load_peers_from_file():
    path = LOCAL_PEER_POOL_PATH
    #load existing pool
    with open(path, 'r') as peer_file:
        existing_peers_raw = peer_file.read()
        existing_peers = json.loads(existing_peers_raw)
    return existing_peers

def load_local_nodes(local_private_key):
    existing_peers = load_peers_from_file()
    peer_pool = []
    for i, peer in enumerate(existing_peers):
        if peer[0] != local_private_key.public_key.to_hex():
            peer_pool.append(Node(keys.PublicKey(decode_hex(peer[0])),Address(peer[1], peer[2], peer[3])))
    return peer_pool
        

    