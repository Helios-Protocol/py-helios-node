from eth_keys import keys
import json
from hvm.constants import TESTNET_FAUCET_PRIVATE_KEY
from hvm.constants import random_private_keys
print(keys.PrivateKey(TESTNET_FAUCET_PRIVATE_KEY).public_key.to_address())

from helios.rlp_templates.hls import (
    BlockHashKey)


from hvm.types import Timestamp

test = 1.232
print(int(test))
print(Timestamp(test))