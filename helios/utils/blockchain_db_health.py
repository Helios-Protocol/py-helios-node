from hvm import MainnetChain
from hvm import constants
from hvm.chains.mainnet import (
    MAINNET_GENESIS_PARAMS,
    MAINNET_GENESIS_STATE,
    GENESIS_PRIVATE_KEY,
)

from hvm.db.backends.level import LevelDB
from hvm.db.journal import JournalDB


def fix_blockchain_database_errors(base_db):
    '''
    Checks to make sure all chains match what is expected from saved chain head root hash
    :param base_db:
    :return:
    '''
    node_1 = MainnetChain(base_db, GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), GENESIS_PRIVATE_KEY)
    chain_head_hashes = node_1.chain_head_db.get_head_block_hashes_list()

    for head_hash in chain_head_hashes:
        address = node_1.chaindb.get_chain_wallet_address_for_block_hash(head_hash)
        # make sure the head block matches the expected head_hash
        chain_head_header = node_1.chaindb.get_canonical_head_hash(address)

        if chain_head_header != head_hash:
            print('fuck')
            exit()

base_db = JournalDB(LevelDB('/home/tommy/.local/share/helios/instance_0/chain'))
fix_blockchain_database_errors(base_db)