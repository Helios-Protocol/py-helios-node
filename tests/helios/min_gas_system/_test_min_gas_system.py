
import time

from helios.utils.xdg import get_xdg_helios_root
from helios_web3 import HeliosWeb3 as Web3
from web3 import WebsocketProvider, IPCProvider

#
# You must manually start the node before running this test
#

helios_home_dir = get_xdg_helios_root()
ipc_path = helios_home_dir / 'instance_0' / 'jsonrpc.ipc'
ipc_path_instance_1 = helios_home_dir / 'instance_1' / 'jsonrpc.ipc'


from hvm.constants import GAS_TX, BLOCK_GAS_LIMIT

from eth_utils import to_wei, encode_hex

from hvm.constants import random_private_keys
from hvm.chains.testnet import (
    TESTNET_GENESIS_PARAMS,
    TESTNET_GENESIS_STATE,
    TESTNET_GENESIS_PRIVATE_KEY,
    TESTNET_NETWORK_ID,
)

from eth_keys import keys

def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(random_private_keys[instance_number])

SENDER = TESTNET_GENESIS_PRIVATE_KEY
RECEIVER = get_primary_node_private_helios_key(1)
RECEIVER2 = get_primary_node_private_helios_key(2)
RECEIVER3 = get_primary_node_private_helios_key(3)
RECEIVER4 = get_primary_node_private_helios_key(4)
RECEIVER5 = get_primary_node_private_helios_key(5)


def prepare_and_sign_block(w3, transactions, from_private_key):
    block_creation_parameters = w3.hls.getBlockCreationParams(encode_hex(from_private_key.public_key.to_canonical_address()))
    # AttributeDict({'block_number': '0x0', 'parent_hash': '0x0000000000000000000000000000000000000000000000000000000000000000', 'nonce': '0x0', 'receive_transactions': [], 'reward_bundle': '0xc5c180c280c0'})


    header_dict = {'blockNumber': block_creation_parameters['block_number'],
                   'parentHash': block_creation_parameters['parent_hash']}

    #
    # Prepare transactions
    #

    nonce = block_creation_parameters['nonce']
    min_gas_price = w3.hls.gasPrice
    min_gas_price = min_gas_price*10
    gas_price = to_wei(min_gas_price, 'gwei')

    for i in range(len(transactions)):
        if 'gas' not in transactions[i]:
            transactions[i]['gas'] = GAS_TX
        transactions[i]['nonce'] = nonce
        transactions[i]['gasPrice'] = gas_price
        nonce = nonce + 1

    signed_block = w3.hls.account.signBlock(send_transaction_dicts=transactions,
                                                 header_dict=header_dict,
                                                 private_key=str(from_private_key))

    return signed_block, header_dict, transactions

def _test_DOS_with_many_transactions_on_rpc():

    # w3 = web3.Web3(web3.IPCProvider(ipc_path))
    w3 = Web3(IPCProvider(ipc_path))
    w3_instance_1 = Web3(IPCProvider(ipc_path))

    start_time = time.time()
    num_transactions = 0

    while True:
        for instance_num in range(10):
            to_account = w3.hls.account.create()
            print("Sending 100 tx from instance {}".format(instance_num))
            txs = []
            for i in range(100):
                txs.append({
                    'to': to_account.address,
                    'value': 1,
                })

                num_transactions += 1

            signed_block, header_dict, transactions = prepare_and_sign_block(w3, txs, get_primary_node_private_helios_key(instance_num))

            response = w3.hls.sendRawBlock(signed_block['rawBlock'])
            time.sleep(1.1)

        tx_per_second = (num_transactions/(time.time()-start_time))
        print("Transactions per second = {}".format(tx_per_second))
        gas_price_instance_0 = w3.hls.gasPrice
        print('gas_price_instance_0 {}'.format(gas_price_instance_0))

        gas_price_instance_1 = w3_instance_1.hls.gasPrice
        print('gas_price_instance_1 {}'.format(gas_price_instance_1))

        time.sleep(4)


_test_DOS_with_many_transactions_on_rpc()
exit()








