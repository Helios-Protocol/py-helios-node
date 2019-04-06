from eth_keys import keys
import json
from hvm.constants import TESTNET_FAUCET_PRIVATE_KEY
from hvm.constants import random_private_keys
print(keys.PrivateKey(TESTNET_FAUCET_PRIVATE_KEY).public_key.to_address())

from helios.rlp_templates.hls import (
    BlockHashKey)

block_hash_key = BlockHashKey(wallet_address = keys.PrivateKey(TESTNET_FAUCET_PRIVATE_KEY).public_key.to_canonical_address(),
                                      block_number = 1,
                                      block_hash = b'test')

# print(block_hash_key.wallet_address)
#
# from eth_account import Account
#
# print(json.dumps(Account.encrypt(TESTNET_FAUCET_PRIVATE_KEY, 'test')))
# print(Account.decrypt(Account.encrypt(TESTNET_FAUCET_PRIVATE_KEY, 'test'), 'test'))
print(keys.PrivateKey(random_private_keys[0]).public_key.to_address())
print(1*10**18)

import codecs
print(codecs.decode('9c8b20e830c0db83862892fc141808ea6a51fea2', "hex"))