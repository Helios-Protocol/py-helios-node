from eth_utils import (
    decode_hex,
    encode_hex,
    int_to_big_endian,
    is_integer,
    big_endian_to_int,
    to_wei,
    from_wei,
    to_checksum_address,
    to_normalized_address,
    keccak,
    to_hex,
)
from eth_utils.curried import (
    to_bytes,
)
from helios.exceptions import BaseRPCError
from helios.rpc.format import (
    format_params,
    dummy,
    to_int_if_hex,)

# Tell mypy to ignore this import as a workaround for https://github.com/python/mypy/issues/4049
from helios.rpc.modules import (  # type: ignore
    RPCModule,
)
from helios.sync.common.constants import FULLY_SYNCED_STAGE_ID
from typing import (
    cast,
    Dict,
    List
)
from helios.rlp_templates.hls import P2PBlock
from hp2p.events import NewBlockEvent, StakeFromBootnodeRequest, CurrentSyncStageRequest, \
    CurrentSyncingParametersRequest, GetConnectedNodesRequest

from eth_keys import keys
from helios_web3 import HeliosWeb3 as Web3
import os
import json
import asyncio
from eth_account.messages import (
    SignableMessage,
)
from eth_typing import Address
from hvm.constants import GAS_TX
from hvm.db.read_only import ReadOnlyDB
import time
from hvm.utils.blocks import does_block_meet_min_gas_price, get_block_average_transaction_gas_price

def encode_defunct(
        primitive: bytes = None,
        *,
        hexstr: str = None,
        text: str = None) -> SignableMessage:
    """
    Encoded as defined here: https://github.com/ethereum/eth-account/blob/master/eth_account/messages.py
    Except with Helios in the message instead of Ethereum
    """
    message_bytes = to_bytes(primitive, hexstr=hexstr, text=text)
    msg_length = str(len(message_bytes)).encode('utf-8')

    # Encoding version E defined by EIP-191
    return SignableMessage(
        b'H',
        b'elios Signed Message:\n' + msg_length,
        message_bytes,
    )

class Personal(RPCModule):
    '''
    All the methods defined by JSON-RPC API, starting with "personal_"...

    Any attribute without an underscore is publicly accessible.
    '''

    _unlocked_accounts = {}
    _account_lock_cancel_events = {}

    _importing_block_lock = asyncio.Lock()

    _account_address_cache = set()
    _account_address_cache_ready = asyncio.Event()

    def __init__(self, *args, **kwargs) -> None:
        # Create the account address cache
        asyncio.ensure_future(self._init_account_address_cache())
        super().__init__(*args, **kwargs)

    def _save_account(self, account, password):
        if not self._account_address_cache_ready.is_set():
            raise BaseRPCError("Account cache is still building. Please wait and try again in a moment.")

        w3 = Web3()
        new_account_json_encrypted = w3.hls.account.encrypt(account.privateKey, password)
        keyfile_name = "HLS_account_{}".format(account.address)
        keyfile_path = self._rpc_context.keystore_dir / keyfile_name

        f = open(str(keyfile_path), "w")
        f.write(json.dumps(new_account_json_encrypted))
        f.close()

        self._account_address_cache.add(account.address)

    def _get_keystore_for_address(self, wallet_address):
        normalized_wallet_address = to_normalized_address(wallet_address)
        file_glob = self._rpc_context.keystore_dir.glob('**/*')
        files = [x for x in file_glob if x.is_file()]
        for json_keystore in files:
            try:
                with open(str(json_keystore)) as json_file:
                    keystore = json.load(json_file)
                    if 'address' in keystore:
                        if normalized_wallet_address == to_normalized_address(keystore['address']):
                            return keystore
            except Exception as e:
                # Not a json file
                pass

        raise BaseRPCError("No saved keystore for wallet address {}".format(normalized_wallet_address))

    #
    # Account Locking and Unlocking Functions
    #

    async def _unlock_account(self, wallet_address: bytes, password: str):
        normalized_wallet_address = to_normalized_address(wallet_address)
        print("Unlocking account {}".format(normalized_wallet_address))
        w3 = Web3()
        keystore = self._get_keystore_for_address(normalized_wallet_address)

        private_key = w3.hls.account.decrypt(keystore, password)
        account = w3.hls.account.privateKeyToAccount(private_key)
        return account

    async def _unlock_account_with_duration(self, wallet_address: bytes, password: str, duration: int = 300):
        normalized_wallet_address = to_normalized_address(wallet_address)
        account = await self._unlock_account(wallet_address, password)

        self._unlocked_accounts[normalized_wallet_address] = account

        if duration == 0:
            if normalized_wallet_address in self._account_lock_cancel_events:
                print("Cancelling previous lock event")
                self._account_lock_cancel_events[normalized_wallet_address].set()
                del (self._account_lock_cancel_events[normalized_wallet_address])

        else:
            asyncio.ensure_future(self._lock_account_after_time(account.address, duration))

    async def _lock_account_after_time(self, wallet_address, duration):
        normalized_wallet_address = to_normalized_address(wallet_address)

        # first check to see if there is already another thread waiting to lock it. If so, cancel that one first.
        if normalized_wallet_address in self._account_lock_cancel_events:
            print("Cancelling previous lock event")
            self._account_lock_cancel_events[normalized_wallet_address].set()

        cancel_event = asyncio.Event()

        self._account_lock_cancel_events[normalized_wallet_address] = cancel_event
        await asyncio.wait([asyncio.sleep(duration), cancel_event.wait()], return_when=asyncio.FIRST_COMPLETED)

        if not cancel_event.is_set():
            print("Locking account {}".format(normalized_wallet_address))
            try:
                del (self._unlocked_accounts[normalized_wallet_address])
            except KeyError:
                pass

            try:
                if self._account_lock_cancel_events[normalized_wallet_address] is cancel_event:
                    del (self._account_lock_cancel_events[normalized_wallet_address])
            except KeyError:
                pass

    async def _get_unlocked_account_or_unlock_now(self, wallet_address: bytes, password: str = None):
        normalized_wallet_address = to_normalized_address(wallet_address)
        if password is None or password == '':
            try:
                account = self._unlocked_accounts[normalized_wallet_address]
            except KeyError:
                raise BaseRPCError("No unlocked account found with wallet address {}".format(normalized_wallet_address))
        else:
            account = await self._unlock_account(wallet_address, password)
        return account




    async def _get_all_account_addresses_set(self):
        file_glob = self._rpc_context.keystore_dir.glob('**/*')
        files = [x for x in file_glob if x.is_file()]
        account_wallet_addresses = set()
        for json_keystore_filename in files:
            # pieces = str(json_keystore_filename).split('HLS_account_')
            # if len(pieces) == 2:
            #     if len(pieces[1]) == 42:
            #         account_wallet_addresses.add(pieces[1])
            #         continue
            try:
                with open(str(json_keystore_filename)) as json_file:
                    keystore = json.load(json_file)
                    if 'address' in keystore:
                        account_wallet_addresses.add(keystore['address'])
            except Exception as e:
                # Not a json file
                pass

        return account_wallet_addresses

    async def _init_account_address_cache(self):
        self._account_address_cache = await self._get_all_account_addresses_set()
        self._account_address_cache_ready.set()

    async def _get_all_account_addresses_set_from_cache(self):
        if not self._account_address_cache_ready.is_set():
            raise BaseRPCError("Account cache is still building. Please wait and try again in a moment.")
        return self._account_address_cache

    #
    # Transaction and Block Creation Functions
    #

    async def _send_transactions(self, transactions, account, include_receive: bool = True):
        async with self._importing_block_lock:
            print("Importing block")
            normalized_wallet_address = to_normalized_address(account.address)

            wallet_address_hex = account.address

            wallet_address = decode_hex(wallet_address_hex)

            chain = self.get_new_chain(Address(wallet_address), account._key_obj)

            allowed_time_of_next_block = chain.get_allowed_time_of_next_block()
            now = int(time.time())

            if now < allowed_time_of_next_block:
                raise BaseRPCError("The minimum time between blocks has not passed. You must wait until {} to send the next block. "
                                   "Use personal_sendTrasactions to send multiple transactions at once.".format(allowed_time_of_next_block))

            # make the chain read only for creating the block. We don't want to actually import it here.
            chain.enable_read_only_db()

            if include_receive:
                chain.populate_queue_block_with_receive_tx()

            signed_transactions = []
            min_gas_price = to_wei(chain.chaindb.get_required_block_min_gas_price(), 'gwei')
            safe_min_gas_price = to_wei(chain.chaindb.get_required_block_min_gas_price()+5, 'gwei')
            for i in range(len(transactions)):
                tx = transactions[i]
                if to_normalized_address(tx['from']) != normalized_wallet_address:
                    raise BaseRPCError("When sending multiple transactions at once, they must all be from the same address")

                if 'gasPrice' in tx:
                    gas_price = to_int_if_hex(tx['gasPrice'])
                else:
                    gas_price = safe_min_gas_price

                if 'gas' in tx:
                    gas = to_int_if_hex(tx['gas'])
                else:
                    gas = GAS_TX

                if 'data' in tx:
                    data = tx['data']
                else:
                    data = b''

                if 'nonce' in tx:
                    nonce = to_int_if_hex(tx['nonce'])
                else:
                    nonce = None

                transactions[i]['nonce'] = nonce
                signed_tx = chain.create_and_sign_transaction_for_queue_block(
                    gas_price=gas_price,
                    gas=gas,
                    to=decode_hex(tx['to']),
                    value=to_int_if_hex(tx['value']),
                    data=data,
                    nonce=nonce,
                    v=0,
                    r=0,
                    s=0
                )
                signed_transactions.append(signed_tx)


            block = chain.import_current_queue_block()

            if not does_block_meet_min_gas_price(block, chain):
                raise Exception("The average gas price of all transactions in your block does not meet the required minimum gas price. Your average block gas price: {}. Min gas price: {}".format(
                    get_block_average_transaction_gas_price(block),
                    min_gas_price))

            if len(signed_transactions) == 0 and len(block.receive_transactions) == 0:
                raise BaseRPCError("Cannot send block if it has no send or receive transactions.")

            self._event_bus.broadcast(
                NewBlockEvent(block=cast(P2PBlock, block), from_rpc=True)
            )

            send_transaction_hashes = [encode_hex(tx.hash) for tx in signed_transactions]
            receive_transaction_hashes = [encode_hex(tx.hash) for tx in block.receive_transactions]
            all_transaction_hashes = send_transaction_hashes
            all_transaction_hashes.extend(receive_transaction_hashes)

            if not include_receive:
                return all_transaction_hashes[0]
            else:
                return all_transaction_hashes

    #
    # Public Personal RPC functions
    #

    @format_params(decode_hex, dummy)
    async def importRawKey(self, keydata: bytes, password: str):
        w3 = Web3()
        new_account = w3.hls.account.privateKeyToAccount(keydata)
        self._save_account(new_account, password)

        return to_checksum_address(new_account.address)

    async def listAccounts(self):
        account_wallet_addresses = list(await self._get_all_account_addresses_set_from_cache())

        return account_wallet_addresses

    @format_params(decode_hex)
    async def lockAccount(self, wallet_address: bytes):
        await self._lock_account_after_time(wallet_address, 0)

    async def newAccount(self, password: str):
        w3 = Web3()
        new_account = w3.hls.account.create()
        self._save_account(new_account, password)

        return to_checksum_address(new_account.address)

    @format_params(decode_hex, dummy, to_int_if_hex)
    async def unlockAccount(self, wallet_address: bytes, password: str, duration: int = 300):
        await self._unlock_account_with_duration(wallet_address, password, duration)


    async def sendTransaction(self, tx, password: str = None):
        # implement this here, and have hls.sendtransaction call this
        '''

        :param tx: {'from', 'to', 'value', 'gas', 'gasPrice', 'data', 'nonce'}
        :param password:
        :return:
        '''

        # Check our current syncing stage. Must be sync stage 4.
        current_sync_stage_response = await self._event_bus.request(
            CurrentSyncStageRequest()
        )
        if current_sync_stage_response.sync_stage < FULLY_SYNCED_STAGE_ID:
            raise BaseRPCError("This node is still syncing with the network. Please wait until this node has synced.")


        wallet_address_hex = tx['from']

        print(tx)

        account = await self._get_unlocked_account_or_unlock_now(wallet_address_hex, password)
        return await self._send_transactions([tx], account, False)


    async def sendTransactions(self, txs, password: str = None):
        '''

        :param tx: {'from', 'to', 'value', 'gas', 'gasPrice', 'data', 'nonce'}
        :param password:
        :return:
        '''

        # Check our current syncing stage. Must be sync stage 4.
        current_sync_stage_response = await self._event_bus.request(
            CurrentSyncStageRequest()
        )
        if current_sync_stage_response.sync_stage < FULLY_SYNCED_STAGE_ID:
            raise BaseRPCError("This node is still syncing with the network. Please wait until this node has synced.")

        wallet_address_hex = txs[0]['from']

        account = await self._get_unlocked_account_or_unlock_now(wallet_address_hex, password)
        return await self._send_transactions(txs, account)

    @format_params(decode_hex, dummy)
    async def receiveTransactions(self, wallet_address: bytes, password: str = None):
        # Check our current syncing stage. Must be sync stage 4.
        current_sync_stage_response = await self._event_bus.request(
            CurrentSyncStageRequest()
        )
        if current_sync_stage_response.sync_stage < FULLY_SYNCED_STAGE_ID:
            raise BaseRPCError("This node is still syncing with the network. Please wait until this node has synced.")

        wallet_address_hex = encode_hex(wallet_address)

        account = await self._get_unlocked_account_or_unlock_now(wallet_address_hex, password)
        return await self._send_transactions([], account)


    @format_params(dummy, decode_hex, dummy)
    async def sign(self, message: str, wallet_address: bytes, password: str = None):
        # using EIP 191 https://github.com/ethereum/eth-account/blob/master/eth_account/messages.py
        normalized_wallet_address = to_normalized_address(wallet_address)
        account = self._get_unlocked_account_or_unlock_now(wallet_address, password)

        signable_message = encode_defunct(text = message)
        w3 = Web3()

        signed_message = w3.hls.account.sign_message(signable_message, account.privateKey)
        return signed_message['signature'].hex()

    @format_params(dummy, decode_hex)
    async def ecRecover(self, message: str, signature: bytes):

        w3 = Web3()
        signable_message = encode_defunct(text=message)
        checksum_address = w3.hls.account.recover_message(signable_message, signature = signature)
        return checksum_address

    @format_params(to_int_if_hex)
    async def getAccountsWithReceivableTransactions(self, after_timestamp):
        hex_encoded_accounts = await self.listAccounts()
        addresses = await self._rpc_context.modules['hls'].filterAddressesWithReceivableTransactions(hex_encoded_accounts, after_timestamp)
        return addresses




