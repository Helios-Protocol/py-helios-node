from eth_keys import keys
import json
from hvm.constants import TESTNET_FAUCET_PRIVATE_KEY
from hvm.constants import random_private_keys
print(keys.PrivateKey(TESTNET_FAUCET_PRIVATE_KEY).public_key.to_address())

from helios.rlp_templates.hls import (
    BlockHashKey)

# block_hash_key = BlockHashKey(wallet_address = keys.PrivateKey(TESTNET_FAUCET_PRIVATE_KEY).public_key.to_canonical_address(),
#                                       block_number = 1,
#                                       block_hash = b'test')

# print(block_hash_key.wallet_address)
#
# from eth_account import Account
#
# print(json.dumps(Account.encrypt(TESTNET_FAUCET_PRIVATE_KEY, 'test')))
# print(Account.decrypt(Account.encrypt(TESTNET_FAUCET_PRIVATE_KEY, 'test'), 'test'))
from hvm.db.trie import _make_trie_root_and_nodes, _make_trie_root_and_nodes_isometric_on_order
from eth_utils import decode_hex
diff_verification_block_hashes = ['0x846d20df081ef9bc482058ec3b2c3d6c4c81b3de33009c8cd8ce3f2d2472a546',
 '0xfbeed83fb24b21c54517d1ca90b36b7a3b68bc69581bf515e168793179a03276',
 '0x104ad1bc07f918c93b0397c9aa1f58845051b85f821a3025847b1c487c1f1f23',
 '0x85bde35140d2d9bc72ba4dc5ba36235bc7e7e7b080af5d75fd2b3b86350bc75c',
 '0x8f2696232540019b70e3b7b034e06cb03c9851074670f45870ed35b8468217fd',
 '0xa3b2420de01ed434c9746b6a16634e45823a4affaae2906115b99d2c1f6e473c',
 '0x1ab5b80d5b2224ce5bda7b43db0092ec9d739274eb9f41585487a5eb7687b980',
 '0x4ca45ba5d2b16918dabfef74bfcde0dcdbe5e2b0db55f33348eecec8e7a95e0e',
 '0x6b1e045d3c0d8f4d8c2f3e387801381fca55a506daa5fda4815f133bf9976629']

diff_verification_block_hashes = [decode_hex(x) for x in diff_verification_block_hashes]
diff_verification_root_hash, _ = _make_trie_root_and_nodes_isometric_on_order(tuple(diff_verification_block_hashes))
print(diff_verification_root_hash)


diff_verification_block_hashes = ['0x846d20df081ef9bc482058ec3b2c3d6c4c81b3de33009c8cd8ce3f2d2472a546',
 '0xfbeed83fb24b21c54517d1ca90b36b7a3b68bc69581bf515e168793179a03276',
 '0x104ad1bc07f918c93b0397c9aa1f58845051b85f821a3025847b1c487c1f1f23',
 '0x85bde35140d2d9bc72ba4dc5ba36235bc7e7e7b080af5d75fd2b3b86350bc75c',
 '0x8f2696232540019b70e3b7b034e06cb03c9851074670f45870ed35b8468217fd',
 '0xa3b2420de01ed434c9746b6a16634e45823a4affaae2906115b99d2c1f6e473c',
 '0x1ab5b80d5b2224ce5bda7b43db0092ec9d739274eb9f41585487a5eb7687b980',
 '0x6b1e045d3c0d8f4d8c2f3e387801381fca55a506daa5fda4815f133bf9976629',
 '0x4ca45ba5d2b16918dabfef74bfcde0dcdbe5e2b0db55f33348eecec8e7a95e0e',
 ]

diff_verification_block_hashes = [decode_hex(x) for x in diff_verification_block_hashes]
diff_verification_root_hash, _ = _make_trie_root_and_nodes_isometric_on_order(tuple(diff_verification_block_hashes))
print(diff_verification_root_hash)


# import codecs
# print(codecs.decode('', "hex"))