import logging
import os
import random
import time
import sys
from pprint import pprint
import pytest

from hvm import constants

from hvm import TestnetChain
from hvm.chains.testnet import (
    TESTNET_GENESIS_PARAMS,
    TESTNET_GENESIS_STATE,
    TESTNET_GENESIS_PRIVATE_KEY,
    TESTNET_NETWORK_ID,
)

from hvm.constants import (
    GAS_TX)
from hvm.exceptions import ReceivableTransactionNotFound, ValidationError

from hvm.vm.forks.boson.constants import MIN_TIME_BETWEEN_BLOCKS
from hvm.db.backends.level import LevelDB
from hvm.db.backends.memory import MemoryDB
from hvm.db.journal import (
    JournalDB,
)

from hvm.db.chain import ChainDB
from hvm.db.trie import make_trie_root_and_nodes
from hvm.rlp.headers import MicroBlockHeader
from hvm.rlp.transactions import BaseTransaction

import rlp as rlp


from eth_utils import (
    encode_hex,
    decode_hex,
)
from helios.dev_tools import create_dev_test_random_blockchain_database, \
    create_dev_test_blockchain_database_with_given_transactions, create_new_genesis_params_and_state, \
    add_transactions_to_blockchain_db
from eth_keys import keys
from sys import exit

from trie import (
    HexaryTrie,
)
from hvm.db.hash_trie import HashTrie

import matplotlib.pyplot as plt

from hvm.db.chain_head import ChainHeadDB

from eth_utils import (
    int_to_big_endian,
    big_endian_to_int,
)
from eth_keys import keys

from hvm.constants import random_private_keys

def get_primary_node_private_helios_key(instance_number = 0):
    return keys.PrivateKey(random_private_keys[instance_number])

from hvm.vm.forks.photon.account import PhotonAccountDB, PhotonAccount
from hvm.db.account import AccountDB
from hvm.rlp.accounts import Account, AccountDepreciated

from hvm.constants import BLANK_ROOT_HASH, EMPTY_SHA3
from hvm.utils.rlp import ensure_rlp_objects_are_equal

def ensure_accounts_are_equal(boson_account, photon_account):
    _ensure_accounts_are_equal = ensure_rlp_objects_are_equal(
        obj_a_name="boson_account",
        obj_b_name="photon_account",
    )

    corrected_boson_account = PhotonAccount(boson_account.nonce,
                                            boson_account.block_number,
                                            boson_account.balance,
                                            boson_account.storage_root,
                                            code_hash=boson_account.code_hash)

    _ensure_accounts_are_equal(corrected_boson_account, photon_account)

def ensure_depreciated_account_equals_boson_account(depreciated_account, boson_account):
    _ensure_accounts_are_equal = ensure_rlp_objects_are_equal(
        obj_a_name="depreciated_account",
        obj_b_name="boson_account",
    )

    corrected_depreciated_account = Account(depreciated_account.nonce,
                                            depreciated_account.block_number,
                                            depreciated_account.balance,
                                            depreciated_account.storage_root,
                                            code_hash=depreciated_account.code_hash)

    _ensure_accounts_are_equal(corrected_depreciated_account, boson_account)

def ensure_depreciated_account_equals_photon(depreciated_account, photon_account):
    _ensure_accounts_are_equal = ensure_rlp_objects_are_equal(
        obj_a_name="depreciated_account",
        obj_b_name="photon_account",
    )

    corrected_depreciated_account = PhotonAccount(depreciated_account.nonce,
                                            depreciated_account.block_number,
                                            depreciated_account.balance,
                                            depreciated_account.storage_root,
                                            code_hash=depreciated_account.code_hash)

    _ensure_accounts_are_equal(corrected_depreciated_account, photon_account)


from hvm.db.schema import SchemaV1
from hvm.rlp.accounts import TransactionKey
from hvm.constants import ZERO_HASH32

def set_old_account(account_db, address, account):
    encoded_account = rlp.encode(account, sedes=AccountDepreciated)

    account_lookup_key = SchemaV1.make_account_lookup_key(address)
    account_db._journaldb[account_lookup_key] = encoded_account

    # set the account version
    account_version_lookup_key = SchemaV1.make_account_version_lookup_key(address)
    try:
        del (account_db._journaldb[account_version_lookup_key])
    except KeyError:
        pass

from eth_typing import Hash32

#
# Boson fork
#
def test_upgrade_from_depreciated_boson():
    test_address = get_primary_node_private_helios_key(0).public_key.to_canonical_address()
    testdb = MemoryDB()

    account_db = AccountDB(testdb)
    depreciated_account = AccountDepreciated(nonce=1,
                                             block_number = 1,
                                             receivable_transactions = [TransactionKey(ZERO_HASH32, ZERO_HASH32)],
                                             balance = 100,
                                             storage_root = ZERO_HASH32,
                                             code_hash = ZERO_HASH32)

    set_old_account(account_db, test_address, depreciated_account)

    boson_account = account_db._get_account(test_address)

    # Make sure the new account is correct
    ensure_depreciated_account_equals_boson_account(depreciated_account, boson_account)

    # Make sure it still has receivable transactions
    receivable_transactions = account_db.get_receivable_transactions(test_address)

    assert(receivable_transactions == [TransactionKey(ZERO_HASH32, ZERO_HASH32)])

    account_db.persist()

    new_account_db = AccountDB(testdb)
    new_account = new_account_db._get_account(test_address)
    assert(new_account == boson_account)





def test_receivable_transactions_boson():
    test_address = get_primary_node_private_helios_key(0).public_key.to_canonical_address()
    testdb = MemoryDB()

    account_db = AccountDB(testdb)

    # save_receivable_transactions
    account_db.save_receivable_transactions(test_address, [TransactionKey(ZERO_HASH32, ZERO_HASH32)])
    receivable_transactions = account_db.get_receivable_transactions(test_address)

    assert(receivable_transactions == [TransactionKey(ZERO_HASH32, ZERO_HASH32)])

    #add_receivable_transaction
    new_hash = Hash32(32 * b'\x01')
    account_db.add_receivable_transaction(test_address, new_hash, new_hash)

    receivable_transactions_2 = account_db.get_receivable_transactions(test_address)

    receivable_transactions.append(TransactionKey(new_hash, new_hash))

    assert (receivable_transactions_2 == receivable_transactions)

    # add_receivable_transaction duplicate transaction
    new_hash = Hash32(32 * b'\x01')
    with pytest.raises(ValueError):
        account_db.add_receivable_transaction(test_address, new_hash, new_hash)


    # add_receivable_transactions
    new_hash_2 = Hash32(32 * b'\x02')
    new_hash_3 = Hash32(32 * b'\x03')
    account_db.add_receivable_transactions(test_address,[TransactionKey(new_hash_2, new_hash_2), TransactionKey(new_hash_3, new_hash_3)])

    receivable_transactions_3 = account_db.get_receivable_transactions(test_address)

    receivable_transactions.extend([TransactionKey(new_hash_2, new_hash_2), TransactionKey(new_hash_3, new_hash_3)])

    assert (receivable_transactions_3 == receivable_transactions)

    # get_receivable_transaction:
    receivable_transaction = account_db.get_receivable_transaction(test_address, new_hash_2)
    assert(receivable_transaction == TransactionKey(new_hash_2, new_hash_2))

    #get missing receivabel transaction
    new_hash_4 = Hash32(32 * b'\x04')
    receivable_transaction = account_db.get_receivable_transaction(test_address, new_hash_4)
    assert(receivable_transaction is None)

    #delete_receivable_transaction
    account_db.delete_receivable_transaction(test_address, new_hash_3)
    del(receivable_transactions[-1])
    receivable_transactions_4 = account_db.get_receivable_transactions(test_address)
    assert (receivable_transactions_4 == receivable_transactions)

    # delete_receivable_transaction missing
    with pytest.raises(ReceivableTransactionNotFound):
        account_db.delete_receivable_transaction(test_address, new_hash_3)



#
# Photon fork
#

def test_upgrade_from_depreciated_photon():
    test_address = get_primary_node_private_helios_key(0).public_key.to_canonical_address()
    testdb = MemoryDB()

    account_db = PhotonAccountDB(testdb)
    depreciated_account = AccountDepreciated(nonce=1,
                                             block_number = 1,
                                             receivable_transactions = [TransactionKey(ZERO_HASH32, ZERO_HASH32)],
                                             balance = 100,
                                             storage_root = ZERO_HASH32,
                                             code_hash = ZERO_HASH32)

    set_old_account(account_db, test_address, depreciated_account)

    photon_account = account_db._get_account(test_address)

    # Make sure the new account is correct
    ensure_depreciated_account_equals_photon(depreciated_account, photon_account)

    # Make sure it still has receivable transactions
    receivable_transactions = account_db.get_receivable_transactions(test_address)

    assert(receivable_transactions == [TransactionKey(ZERO_HASH32, ZERO_HASH32)])

    account_db._set_account(test_address, account_db._get_account(test_address))
    account_db.persist()

    new_account_db = PhotonAccountDB(testdb)
    new_account = new_account_db._get_account(test_address)
    assert(new_account == photon_account)

    # Make sure boson account throws an error if try to load this
    new_account_db = AccountDB(testdb)
    with pytest.raises(ValidationError):
        new_account_db._get_account(test_address)


def test_version():
    test_address = get_primary_node_private_helios_key(0).public_key.to_canonical_address()
    testdb = MemoryDB()

    old_account_db = AccountDB(testdb)
    assert(old_account_db.version == 0)

    photon_account_db = PhotonAccountDB(testdb)
    assert (photon_account_db.version == 1)



def test_photon_account_db_upgrade_format():
    test_address = get_primary_node_private_helios_key(0).public_key.to_canonical_address()
    testdb = MemoryDB()

    old_account_db = AccountDB(testdb)
    old_account = Account()
    old_account_db._set_account(address = test_address, account = old_account)
    old_account_db.persist()

    photon_account_db = PhotonAccountDB(testdb)
    photon_account = photon_account_db._get_account(test_address)

    ensure_accounts_are_equal(old_account, photon_account)

    if not isinstance(photon_account, PhotonAccount):
        raise Exception("PhotonAccountDB gave incorrect account type")

    #
    # test saving new photon account
    #
    photon_account_db._set_account(test_address, photon_account)
    photon_account = photon_account_db._get_account(test_address)

    ensure_accounts_are_equal(old_account, photon_account)


    #
    # Test setting something like the balance
    #
    photon_account_db.set_balance(test_address, 100)
    balance = photon_account_db.get_balance(test_address)

    assert(balance == 100)




def test_photon_account_db_smart_contract_storage():
    test_address = get_primary_node_private_helios_key(0).public_key.to_canonical_address()
    smart_contract_address = get_primary_node_private_helios_key(1).public_key.to_canonical_address()

    testdb = MemoryDB()
    photon_account_db = PhotonAccountDB(testdb)

    #
    # Load when doesnt exist
    #
    storage_at_0 = photon_account_db.get_smart_contract_storage(test_address, smart_contract_address, 0)
    assert(storage_at_0 == 0)

    #
    # Set, then load
    #
    photon_account_db.set_smart_contract_storage(test_address, smart_contract_address, 0, 100)
    storage_at_0 = photon_account_db.get_smart_contract_storage(test_address, smart_contract_address, 0)
    assert(storage_at_0 == 100)

    #
    # Set another slot, then load both
    #
    photon_account_db.set_smart_contract_storage(test_address, smart_contract_address, 1, 200)
    storage_at_0 = photon_account_db.get_smart_contract_storage(test_address, smart_contract_address, 0)
    storage_at_1 = photon_account_db.get_smart_contract_storage(test_address, smart_contract_address, 1)
    assert (storage_at_0 == 100)
    assert (storage_at_1 == 200)

    #
    # Overwrite, then load both
    #
    photon_account_db.set_smart_contract_storage(test_address, smart_contract_address, 0, 300)
    photon_account_db.set_smart_contract_storage(test_address, smart_contract_address, 1, 400)
    storage_at_0 = photon_account_db.get_smart_contract_storage(test_address, smart_contract_address, 0)
    storage_at_1 = photon_account_db.get_smart_contract_storage(test_address, smart_contract_address, 1)
    assert (storage_at_0 == 300)
    assert (storage_at_1 == 400)

    #
    # Delete, then load
    #
    photon_account_db.delete_smart_contract_storage(test_address, smart_contract_address)
    storage_at_0 = photon_account_db.get_smart_contract_storage(test_address, smart_contract_address, 0)
    assert (storage_at_0 == 0)


def test_photon_account_db_save_root_hash():
    test_address = get_primary_node_private_helios_key(0).public_key.to_canonical_address()
    testdb = MemoryDB()
    photon_account_db = PhotonAccountDB(testdb)

    photon_account_db.set_balance(test_address, 100)
    photon_account_db.persist()
    saved_account_hash = photon_account_db.get_account_hash(test_address)
    photon_account_db.save_current_account_with_hash_lookup(test_address)

    photon_account_db.set_balance(test_address, 200)

    photon_account_db.revert_to_account_from_hash(saved_account_hash, test_address)
    balance = photon_account_db.get_balance(test_address)
    assert(balance == 100)

# test_upgrade_from_depreciated_photon()
# test_upgrade_from_depreciated_boson()
# test_receivable_transactions_boson()
# test_version()
# test_photon_account_db_upgrade_format()
# test_photon_account_db_smart_contract_storage()
# test_photon_account_db_save_root_hash()