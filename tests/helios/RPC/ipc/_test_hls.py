import pytest
import time

from helios.utils.xdg import get_xdg_helios_root
from helios_web3 import HeliosWeb3 as Web3
from web3 import IPCProvider
#
# You must manually start the node before running this test
#
# To run these tests, first start the node with a fresh db using the command:
# python main.py --instance 0 --network_startup_node --rand_db --enable_private_rpc
#

helios_home_dir = get_xdg_helios_root()
ipc_path = helios_home_dir / 'instance_0' / 'jsonrpc.ipc'

from hvm.constants import random_private_keys

from eth_keys import keys

def instance(instance_number = 0):
    return keys.PrivateKey(random_private_keys[instance_number])



test_password = '1234abcd'

def _test_simple_responses():
    w3 = Web3(IPCProvider(ipc_path))

    ping = w3.hls.ping
    assert(ping == True)

    block_number = w3.hls.blockNumber(instance(1).public_key.to_checksum_address())
    assert(block_number == 0)

    gas_price = w3.hls.gasPrice
    assert(gas_price == 1)

    gas_price = w3.hls.getGasPrice()
    assert(gas_price == 1)

    protocol_version = w3.hls.protocolVersion
    assert(protocol_version == '63')

    syncing = w3.hls.syncing
    assert(syncing == False)

_test_simple_responses()


# still to do:
# getBalance
# getBlockTransactionCountByHash
# getBlockTransactionCountByNumber
# getCode
# getStorageAt
# getTransactionByBlockHashAndIndex
# getTransactionByBlockNumberAndIndex
# getTransactionCount
# getTransactionByHash
# getTransactionReceipt
# getReceivableTransactions



