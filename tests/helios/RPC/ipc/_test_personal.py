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

def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(random_private_keys[instance_number])


test_password = '1234abcd'

def _test_key_management():
    w3 = Web3(IPCProvider(ipc_path))
    #
    # Import a raw key
    #
    print("Creating new account")
    new_account = w3.hls.account.create()
    private_key = new_account.key
    w3.personal.importRawKey(private_key, test_password)

    #
    # List the account
    #
    print("Listing accounts")
    list_of_accounts = w3.personal.listAccounts()
    assert(new_account.address in list_of_accounts)

    #
    # Load the account
    #
    print("Unlocking account with incorrect password")
    with pytest.raises(ValueError):
        w3.personal.unlockAccount(new_account.address, 'incorrect')

    print("Unlocking account with correct password")
    w3.personal.unlockAccount(new_account.address, test_password)

    #
    # New Account
    #
    new_account_address_hex = w3.personal.newAccount(test_password)

    #
    # List the account
    #
    print("Listing accounts")
    list_of_accounts = w3.personal.listAccounts()
    assert (new_account_address_hex in list_of_accounts)

    print("Unlocking account with incorrect password")
    with pytest.raises(ValueError):
        w3.personal.unlockAccount(new_account_address_hex, 'incorrect')

    print("Unlocking account with correct password")
    w3.personal.unlockAccount(new_account_address_hex, test_password)





def _test_send_receive_transaction():
    w3 = Web3(IPCProvider(ipc_path))
    INSTANCE_0 = get_primary_node_private_helios_key(0)

    new_account_address_hex = w3.personal.newAccount(test_password)

    tx = {'from': INSTANCE_0.public_key.to_checksum_address(),
          'to': new_account_address_hex,
          'value': 1}

    print("Sending transaction")
    tx_hash = w3.personal.sendTransaction(tx, 'dev')

    #
    # Make sure the hash exists
    #
    time.sleep(0.5)
    # If it doesnt exist, it will throw an exception
    print("Checking transaction exists")
    tx_from_node = w3.hls.getTransaction(tx_hash)

    #
    # Receive the transaction
    #
    print("Receiving transaction")
    tx_hashes = w3.personal.receiveTransactions(new_account_address_hex, test_password)

    #
    # Make sure the hash exists
    #
    time.sleep(0.5)
    # If it doesnt exist, it will throw an exception
    print("Checking transaction exists")
    tx_from_node = w3.hls.getTransaction(tx_hashes[0])




def _test_send_receive_transactions():
    w3 = Web3(IPCProvider(ipc_path))
    INSTANCE_0 = get_primary_node_private_helios_key(0)

    new_account_address_hex_1 = w3.personal.newAccount(test_password)
    new_account_address_hex_2 = w3.personal.newAccount(test_password)

    tx = [{'from': INSTANCE_0.public_key.to_checksum_address(),
          'to': new_account_address_hex_1,
          'value': 1},
          {'from': INSTANCE_0.public_key.to_checksum_address(),
           'to': new_account_address_hex_1,
           'value': 1},
          {'from': INSTANCE_0.public_key.to_checksum_address(),
           'to': new_account_address_hex_2,
           'value': 1}]

    print("Sending transaction")
    tx_hashes = w3.personal.sendTransactions(tx, 'dev')

    #
    # Make sure the hashes exists
    #
    time.sleep(0.5)
    # If it doesnt exist, it will throw an exception
    print("Checking transaction exists")
    tx_from_node = w3.hls.getTransaction(tx_hashes[0])
    tx_from_node = w3.hls.getTransaction(tx_hashes[1])

    #
    # Receive the transaction
    #
    print("Receiving transactions")
    tx_hashes_1 = w3.personal.receiveTransactions(new_account_address_hex_1, test_password)
    tx_hashes_2 = w3.personal.receiveTransactions(new_account_address_hex_2, test_password)

    #
    # Make sure the hash exists
    #
    time.sleep(0.5)
    # If it doesnt exist, it will throw an exception
    print("Checking transactions exists")
    tx_from_node = w3.hls.getTransaction(tx_hashes_1[0])
    tx_from_node = w3.hls.getTransaction(tx_hashes_1[1])
    tx_from_node = w3.hls.getTransaction(tx_hashes_2[0])



def _test_send_receive_transaction_delayed_unlock():
    w3 = Web3(IPCProvider(ipc_path))
    INSTANCE_0 = get_primary_node_private_helios_key(0)

    new_account_address_hex = w3.personal.newAccount(test_password)

    tx = {'from': INSTANCE_0.public_key.to_checksum_address(),
          'to': new_account_address_hex,
          'value': 1}

    print("Unlocking account")
    w3.personal.unlockAccount(INSTANCE_0.public_key.to_checksum_address(), 'dev', 5)
    print("Sending transaction")
    tx_hash = w3.personal.sendTransaction(tx)

    #
    # Make sure the hash exists
    #
    time.sleep(0.5)
    # If it doesnt exist, it will throw an exception
    print("Checking transaction exists")
    tx_from_node = w3.hls.getTransaction(tx_hash)

    #
    # Unlock account for time that is too short
    #
    print("Unlocking account")
    w3.personal.unlockAccount(INSTANCE_0.public_key.to_checksum_address(), 'dev', 1)
    time.sleep(1)
    print("Sending transaction")
    with pytest.raises(ValueError):
        w3.personal.sendTransaction(tx)

    #
    # Unlock twice, and make sure it replaces the old time with the new one
    #

    print("Unlocking account")
    w3.personal.unlockAccount(INSTANCE_0.public_key.to_checksum_address(), 'dev', 300)
    w3.personal.unlockAccount(INSTANCE_0.public_key.to_checksum_address(), 'dev', 1)
    time.sleep(1)
    print("Sending transaction")
    with pytest.raises(ValueError):
        w3.personal.sendTransaction(tx)

    #
    # Unlock twice, and make sure it replaces the old time with the new one
    #

    print("Unlocking account")
    w3.personal.unlockAccount(INSTANCE_0.public_key.to_checksum_address(), 'dev', 2)
    w3.personal.unlockAccount(INSTANCE_0.public_key.to_checksum_address(), 'dev', 300)
    time.sleep(3)
    print("Sending transaction")
    tx_hash = w3.personal.sendTransaction(tx)

    #
    # Make sure the hash exists
    #
    time.sleep(0.5)
    # If it doesnt exist, it will throw an exception
    print("Checking transaction exists")
    tx_from_node = w3.hls.getTransaction(tx_hash)

    #
    # Unlock the account, then lock it before trying to send. Make sure it locked
    #


    print("Unlocking account")
    w3.personal.unlockAccount(INSTANCE_0.public_key.to_checksum_address(), 'dev', 300)
    w3.personal.lockAccount(INSTANCE_0.public_key.to_checksum_address())
    print("Sending transaction")
    with pytest.raises(ValueError):
        w3.personal.sendTransaction(tx)


def _test_get_accounts_with_receivable_transactions():
    w3 = Web3(IPCProvider(ipc_path))
    INSTANCE_0 = get_primary_node_private_helios_key(0)

    new_account_address_hex_1 = w3.personal.newAccount(test_password)
    new_account_address_hex_2 = w3.personal.newAccount(test_password)

    tx = [{'from': INSTANCE_0.public_key.to_checksum_address(),
          'to': new_account_address_hex_1,
          'value': 1},
          {'from': INSTANCE_0.public_key.to_checksum_address(),
           'to': new_account_address_hex_1,
           'value': 1},
          {'from': INSTANCE_0.public_key.to_checksum_address(),
           'to': new_account_address_hex_2,
           'value': 1}]

    print("Sending transactions")
    w3.personal.sendTransactions(tx, 'dev')

    time.sleep(0.5)

    print("Getting accounts over all time")
    accounts_with_receivable = w3.personal.getAccountsWithReceivableTransactions()
    assert(new_account_address_hex_1 in accounts_with_receivable and new_account_address_hex_2 in accounts_with_receivable)

    print("Getting accounts over short time")
    accounts_with_receivable = w3.personal.getAccountsWithReceivableTransactions(int(time.time())-10)
    assert(new_account_address_hex_1 in accounts_with_receivable and new_account_address_hex_2 in accounts_with_receivable)

    print("Getting accounts over future time")
    accounts_with_receivable = w3.personal.getAccountsWithReceivableTransactions(int(time.time())+1)
    assert(accounts_with_receivable == [])

    print("Receiving transactions")
    w3.personal.receiveTransactions(new_account_address_hex_1, test_password)
    w3.personal.receiveTransactions(new_account_address_hex_2, test_password)

    time.sleep(0.5)

    print("Getting accounts over all time")
    accounts_with_receivable = w3.personal.getAccountsWithReceivableTransactions()
    assert(new_account_address_hex_1 not in accounts_with_receivable and new_account_address_hex_2 not in accounts_with_receivable)

    print("Getting accounts over short time")
    accounts_with_receivable = w3.personal.getAccountsWithReceivableTransactions(int(time.time())-10)
    assert(new_account_address_hex_1 not in accounts_with_receivable and new_account_address_hex_2 not in accounts_with_receivable)



def _test_signing_messages():
    w3 = Web3(IPCProvider(ipc_path))
    INSTANCE_0 = get_primary_node_private_helios_key(0)
    message = 'my_cool_message'
    signature = w3.personal.sign(message, INSTANCE_0.public_key.to_canonical_address(), 'dev')

    recovered_address = w3.personal.ecRecover(message, signature)

    assert(recovered_address == INSTANCE_0.public_key.to_checksum_address())



_test_key_management()
_test_send_receive_transaction()
print("Waiting 10 seconds before we can import the next block")
time.sleep(10)
_test_send_receive_transactions()
print("Waiting 10 seconds before we can import the next block")
time.sleep(10)
_test_send_receive_transaction_delayed_unlock()
print("Waiting 10 seconds before we can import the next block")
time.sleep(10)
_test_get_accounts_with_receivable_transactions()
print("Waiting 10 seconds before we can import the next block")
time.sleep(10)
_test_signing_messages()





