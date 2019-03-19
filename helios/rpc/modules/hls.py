from cytoolz import (
    identity,
)
from eth_typing import Hash32

from eth_utils import (
    decode_hex,
    encode_hex,
    int_to_big_endian,
    is_integer,
)
import time

from helios.exceptions import BaseRPCError
from helios.rpc.constants import MAX_ALLOWED_AGE_OF_NEW_RPC_BLOCK
from helios.rpc.format import (
    block_to_dict,
    header_to_dict,
    format_params,
    to_int_if_hex,
    transaction_to_dict,
    receipt_to_dict, receive_transactions_to_dict)
import rlp_cython as rlp
from helios.sync.common.constants import FULLY_SYNCED_STAGE_ID

from hvm.exceptions import CanonicalHeadNotFound
from hvm.utils.blocks import get_block_average_transaction_gas_price

from hvm.types import Timestamp

#from hp2p.chain import NewBlockQueueItem

from eth_utils import is_hex_address, to_checksum_address

# Tell mypy to ignore this import as a workaround for https://github.com/python/mypy/issues/4049
from helios.rpc.modules import (  # type: ignore
    RPCModule,
)

from hvm.utils.headers import (
    compute_gas_limit,
)
from hvm.chains.base import BaseChain

from helios.rlp_templates.hls import P2PBlock

import asyncio

from typing import cast

from hp2p.events import NewBlockEvent, StakeFromBootnodeRequest, CurrentSyncStageRequest, \
    CurrentSyncingParametersRequest

from hvm.rlp.consensus import StakeRewardBundle
from hvm.vm.forks.helios_testnet.blocks import MicroBlock


# def get_header(chain, at_block):
#     if at_block == 'pending':
#         at_header = chain.header
#     elif at_block == 'latest':
#         at_header = chain.get_canonical_head()
#     elif at_block == 'earliest':
#         # TODO find if genesis block can be non-zero. Why does 'earliest' option even exist?
#         at_header = chain.get_canonical_block_by_number(0).header
#     elif is_integer(at_block) and at_block >= 0:
#         at_header = chain.get_canonical_block_by_number(at_block).header
#     else:
#         raise TypeError("Unrecognized block reference: %r" % at_block)
#
#     return at_header


# def account_db_at_block(chain, at_block, read_only=True):
#     at_header = get_header(chain, at_block)
#     vm = chain.get_vm(at_header)
#     return vm.state.account_db


# def get_block_at_number(chain, at_block):
#     if is_integer(at_block) and at_block >= 0:
#         # optimization to avoid requesting block, then header, then block again
#         return chain.get_canonical_block_by_number(at_block)
#     else:
#         at_header = get_header(chain, at_block)
#         return chain.get_block_by_header(at_header)

#TODO: if sync stage is less than 3, don't accept new blocks.
class Hls(RPCModule):
    '''
    All the methods defined by JSON-RPC API, starting with "hls_"...

    Any attribute without an underscore is publicly accessible.
    '''

    #
    # Tools
    #
    async def ping(self) -> bool:
        """
        Workaround for keepalive of ws connections in case it is not handled by the ws client.
        """
        return True

    def accounts(self):
        raise NotImplementedError()

    def blockNumber(self, chain_address):
        num = self._chain.get_canonical_head(chain_address).block_number
        return hex(num)

    def coinbase(self):
        raise NotImplementedError()
        

    def gasPrice(self):
        raise NotImplementedError()

    @format_params(decode_hex, to_int_if_hex)
    async def getBalance(self, address, at_block):
        chain = self._chain_class(self._chain.db, wallet_address=address)

        if at_block == 'latest':
            try:
                header = chain.chaindb.get_canonical_head(address)
                balance = header.account_balance
            except CanonicalHeadNotFound:
                balance = 0
        else:
            header = chain.chaindb.get_canonical_block_header_by_number(at_block, address)
            balance = header.account_balance

        return hex(balance)





    @format_params(decode_hex)
    def getBlockTransactionCountByHash(self, block_hash):
        block = self._chain.get_block_by_hash(block_hash)
        return hex(len(block.transactions))

    @format_params(to_int_if_hex)
    def getBlockTransactionCountByNumber(self, at_block):
        block = get_block_at_number(self._chain, at_block)
        return hex(len(block.transactions))

    @format_params(decode_hex, to_int_if_hex)
    def getCode(self, address, at_block):
        account_db = account_db_at_block(self._chain, at_block)
        code = account_db.get_code(address)
        return encode_hex(code)

    @format_params(decode_hex, to_int_if_hex, to_int_if_hex)
    def getStorageAt(self, address, position, at_block):
        if not is_integer(position) or position < 0:
            raise TypeError("Position of storage must be a whole number, but was: %r" % position)

        account_db = account_db_at_block(self._chain, at_block)
        stored_val = account_db.get_storage(address, position)
        return encode_hex(int_to_big_endian(stored_val))

    @format_params(decode_hex, to_int_if_hex)
    def getTransactionByBlockHashAndIndex(self, block_hash, index):
        block = self._chain.get_block_by_hash(block_hash)
        transaction = block.transactions[index]
        return transaction_to_dict(transaction)

    @format_params(to_int_if_hex, to_int_if_hex)
    def getTransactionByBlockNumberAndIndex(self, at_block, index):
        block = get_block_at_number(self._chain, at_block)
        transaction = block.transactions[index]
        return transaction_to_dict(transaction)

    @format_params(decode_hex, to_int_if_hex)
    def getTransactionCount(self, address, at_block):
        account_db = account_db_at_block(self._chain, at_block)
        nonce = account_db.get_nonce(address)
        return hex(nonce)

    @format_params(decode_hex)
    def getUncleCountByBlockHash(self, block_hash):
        block = self._chain.get_block_by_hash(block_hash)
        return hex(len(block.uncles))

    @format_params(to_int_if_hex)
    def getUncleCountByBlockNumber(self, at_block):
        block = get_block_at_number(self._chain, at_block)
        return hex(len(block.uncles))

    @format_params(decode_hex, to_int_if_hex)
    def getUncleByBlockHashAndIndex(self, block_hash, index):
        block = self._chain.get_block_by_hash(block_hash)
        uncle = block.uncles[index]
        return header_to_dict(uncle)

    @format_params(to_int_if_hex, to_int_if_hex)
    def getUncleByBlockNumberAndIndex(self, at_block, index):
        block = get_block_at_number(self._chain, at_block)
        uncle = block.uncles[index]
        return header_to_dict(uncle)

    def hashrate(self):
        raise NotImplementedError()

    def mining(self):
        return False

    def protocolVersion(self):
        return "63"

    def syncing(self):
        raise NotImplementedError()
        
    #Helios dev functions

    async def devDeploySmartContract(self):
        from hvm.constants import CREATE_CONTRACT_ADDRESS

        from hvm.chains.mainnet import (
            GENESIS_PRIVATE_KEY,
            GENESIS_WALLET_ADDRESS,
        )

        self._chain.set_new_wallet_address(wallet_address=GENESIS_WALLET_ADDRESS, private_key=GENESIS_PRIVATE_KEY)
        self._chain.reinitialize()
        self._chain.enable_journal_db()
        journal_record = self._chain.record_journal()

        smart_contract_data = '0x608060405234801561001057600080fd5b50601260ff16600a0a61271002600181905550601260ff16600a0a612710026000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055503373ffffffffffffffffffffffffffffffffffffffff1660007fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef601260ff16600a0a612710026040518082815260200191505060405180910390a361129e806100db6000396000f3006080604052600436106100ba576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806306fdde03146100bf578063095ea7b31461014f57806318160ddd146101b457806323b872dd146101df5780632ff2e9dc14610264578063313ce5671461028f57806366188463146102c057806370a082311461032557806395d89b411461037c578063a9059cbb1461040c578063d73dd62314610471578063dd62ed3e146104d6575b600080fd5b3480156100cb57600080fd5b506100d461054d565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156101145780820151818401526020810190506100f9565b50505050905090810190601f1680156101415780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561015b57600080fd5b5061019a600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610586565b604051808215151515815260200191505060405180910390f35b3480156101c057600080fd5b506101c9610678565b6040518082815260200191505060405180910390f35b3480156101eb57600080fd5b5061024a600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506106bb565b604051808215151515815260200191505060405180910390f35b34801561027057600080fd5b50610279610a75565b6040518082815260200191505060405180910390f35b34801561029b57600080fd5b506102a4610a84565b604051808260ff1660ff16815260200191505060405180910390f35b3480156102cc57600080fd5b5061030b600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610a89565b604051808215151515815260200191505060405180910390f35b34801561033157600080fd5b50610366600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610d1a565b6040518082815260200191505060405180910390f35b34801561038857600080fd5b50610391610d62565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156103d15780820151818401526020810190506103b6565b50505050905090810190601f1680156103fe5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561041857600080fd5b50610457600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610d9b565b604051808215151515815260200191505060405180910390f35b34801561047d57600080fd5b506104bc600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610fba565b604051808215151515815260200191505060405180910390f35b3480156104e257600080fd5b50610537600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506111b6565b6040518082815260200191505060405180910390f35b6040805190810160405280600b81526020017f53696d706c65546f6b656e00000000000000000000000000000000000000000081525081565b600081600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040518082815260200191505060405180910390a36001905092915050565b60007f24abdb5865df5079dcc5ac590ff6f01d5c16edbc5fab4e195d9febd1114503da6001546040518082815260200191505060405180910390a1600154905090565b60008073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16141515156106f857600080fd5b6000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054821115151561074557600080fd5b600260008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205482111515156107d057600080fd5b610821826000808773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461123d90919063ffffffff16565b6000808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506108b4826000808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461125690919063ffffffff16565b6000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555061098582600260008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461123d90919063ffffffff16565b600260008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a3600190509392505050565b601260ff16600a0a6127100281565b601281565b600080600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905080831115610b9a576000600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550610c2e565b610bad838261123d90919063ffffffff16565b600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055505b8373ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546040518082815260200191505060405180910390a3600191505092915050565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b6040805190810160405280600381526020017f53494d000000000000000000000000000000000000000000000000000000000081525081565b60008073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1614151515610dd857600080fd5b6000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020548211151515610e2557600080fd5b610e76826000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461123d90919063ffffffff16565b6000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550610f09826000808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461125690919063ffffffff16565b6000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a36001905092915050565b600061104b82600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461125690919063ffffffff16565b600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546040518082815260200191505060405180910390a36001905092915050565b6000600260008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b600082821115151561124b57fe5b818303905092915050565b6000818301905082811015151561126957fe5b809050929150505600a165627a7a723058203065ebd182d2e9529433f647283c9d4f1f9e7d600744ec301b2a0aae6a250a530029'

        max_gas = 20000000

        self._chain.create_and_sign_transaction_for_queue_block(
            gas_price=0x01,
            gas=max_gas,
            to=CREATE_CONTRACT_ADDRESS,
            value=0,
            data=decode_hex(smart_contract_data),
            v=0,
            r=0,
            s=0
        )

        block_to_import = self._chain.import_current_queue_block()

        self._chain.discard_journal(journal_record)
        self._chain.disable_journal_db()

        self._event_bus.broadcast(
            NewBlockEvent(block=cast(P2PBlock, block_to_import), only_propogate_to_network=False)
        )

        return []




    async def devAddValidNewBlock(self, version):
        if version == 1:
            '''
            import a valid block
            '''
            from eth_keys import keys

            from hvm.constants import random_private_keys
            #primary_private_keys = [b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5', b'\xa41\x95@\xbb\xa5\xde\xbbc\xffR\x8a\x18\x06\x95\xa3\xd7\xd2\x95]5{\x12\xe4n\xb6R\xd7S\x96\xf0+', b'\xd8>Fh\xefT\x04jf\x13\xca|E\xc4\x91\xed\x07\xcd\x02fW\xd8s;\xd8\xe4\xde\xb9\xbc\xe4\xf0I', b'\x83\x1d\xf6\xaf-\x00\xbfS4\x0f\xcds\x18"\xdd\x906]e\xfc\xe6\x0c?\xb1v20\xced7y\xf4', b")M\xf4\x1c\xb7\xe0Z\xf4\x17F\x9b\x089'\x004\xd3\x89\xd8\x80\xf5`\xa2\x11\x00\x90\xbd\x0f&KjZ", b'RI\xda\xbc7\xc4\xe8\tz\xfaI\x1f\xa1\x02{v\x0e\xac\x87W\xa2s\x81L4M\xad\xbd\xb3\x84\xaae', b'>kG\xd5\xb3qG\x84\xa6"\x1c~\xb6\xbf\x96\xac\n\x88\xfb\x05\x8aG\r\xe9Z\x16\x15\xb1P\xe0\xb7[', b'\x87\xf6\xb1\xa7v\x8bv<\xa3\xe5\xb18\xa7u\x99\xbaBa\xe9\xd5\x0e\xcb\x0f?\x84nZ\xba\xdf\xa3\x8a~', b'`$g\xe9\xa5r\xd2\xacG&\xf81^\x98\xf7\xda\xa5\xf4\x93)\xf3\x0c\x18\x84\xe4)!\x9dR\xa0\xac\xd3', b'\xcfd\xd5|\xe2\xf1\xda\xb9\x1f|\xb9\xdc\xeb \xd7\xb0\x81g\xdc\x03\xd6dQ\xf14\x19`\x94o\xf7\xc7\x1b', b'}LO\x14($d\n!\x1a\x91\xa8S\xb3\x05\xaa\x89\xf2\x0b\x97\xd3\x1c#\xe7\x86g`\xf1\x1a\xedXW']

            def get_primary_node_private_helios_key(instance_number = 0):
                return keys.PrivateKey(random_private_keys[instance_number])

            from hvm.chains.mainnet import (
                GENESIS_PRIVATE_KEY,
                GENESIS_WALLET_ADDRESS,
            )

            SENDER = GENESIS_PRIVATE_KEY
            RECEIVER = get_primary_node_private_helios_key(1)
            RECEIVER2 = get_primary_node_private_helios_key(2)
            RECEIVER3 = get_primary_node_private_helios_key(3)
            RECEIVER4 = get_primary_node_private_helios_key(4)



            #create tx and blocks from the genesis block.
            self._chain.set_new_wallet_address(wallet_address = RECEIVER4.public_key.to_canonical_address(), private_key = RECEIVER4)
            self._chain.reinitialize()
            self._chain.enable_journal_db()
            journal_record = self._chain.record_journal()

            self._chain.create_and_sign_transaction_for_queue_block(
                gas_price=0x01,
                gas=0x0c3500,
                to=RECEIVER.public_key.to_canonical_address(),
                value=1,
                data=b"",
                v=0,
                r=0,
                s=0
                )

            block_to_import = self._chain.import_current_queue_block()

            self._chain.discard_journal(journal_record)
            self._chain.disable_journal_db()

            self._event_bus.broadcast(
                NewBlockEvent(block = cast(P2PBlock, block_to_import), only_propogate_to_network=False)
            )

            return []
        elif version == 2:
            '''
            import a valid block
            '''
            from eth_keys import keys

            # primary_private_keys = [
            #     b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5',
            #     b'\xa41\x95@\xbb\xa5\xde\xbbc\xffR\x8a\x18\x06\x95\xa3\xd7\xd2\x95]5{\x12\xe4n\xb6R\xd7S\x96\xf0+',
            #     b'\xd8>Fh\xefT\x04jf\x13\xca|E\xc4\x91\xed\x07\xcd\x02fW\xd8s;\xd8\xe4\xde\xb9\xbc\xe4\xf0I',
            #     b'\x83\x1d\xf6\xaf-\x00\xbfS4\x0f\xcds\x18"\xdd\x906]e\xfc\xe6\x0c?\xb1v20\xced7y\xf4',
            #     b")M\xf4\x1c\xb7\xe0Z\xf4\x17F\x9b\x089'\x004\xd3\x89\xd8\x80\xf5`\xa2\x11\x00\x90\xbd\x0f&KjZ",
            #     b'RI\xda\xbc7\xc4\xe8\tz\xfaI\x1f\xa1\x02{v\x0e\xac\x87W\xa2s\x81L4M\xad\xbd\xb3\x84\xaae',
            #     b'>kG\xd5\xb3qG\x84\xa6"\x1c~\xb6\xbf\x96\xac\n\x88\xfb\x05\x8aG\r\xe9Z\x16\x15\xb1P\xe0\xb7[',
            #     b'\x87\xf6\xb1\xa7v\x8bv<\xa3\xe5\xb18\xa7u\x99\xbaBa\xe9\xd5\x0e\xcb\x0f?\x84nZ\xba\xdf\xa3\x8a~',
            #     b'`$g\xe9\xa5r\xd2\xacG&\xf81^\x98\xf7\xda\xa5\xf4\x93)\xf3\x0c\x18\x84\xe4)!\x9dR\xa0\xac\xd3',
            #     b'\xcfd\xd5|\xe2\xf1\xda\xb9\x1f|\xb9\xdc\xeb \xd7\xb0\x81g\xdc\x03\xd6dQ\xf14\x19`\x94o\xf7\xc7\x1b',
            #     b'}LO\x14($d\n!\x1a\x91\xa8S\xb3\x05\xaa\x89\xf2\x0b\x97\xd3\x1c#\xe7\x86g`\xf1\x1a\xedXW']

            def get_primary_node_private_helios_key(instance_number=0):
                return keys.PrivateKey(random_private_keys[instance_number])

            from hvm.chains.mainnet import (
                GENESIS_PRIVATE_KEY,
                GENESIS_WALLET_ADDRESS,
            )

            SENDER = GENESIS_PRIVATE_KEY
            RECEIVER = get_primary_node_private_helios_key(1)
            RECEIVER2 = get_primary_node_private_helios_key(2)
            RECEIVER3 = get_primary_node_private_helios_key(3)
            RECEIVER4 = get_primary_node_private_helios_key(4)

            # create tx and blocks from the genesis block.
            self._chain.set_new_wallet_address(wallet_address=GENESIS_WALLET_ADDRESS, private_key=GENESIS_PRIVATE_KEY)
            self._chain.reinitialize()
            self._chain.enable_journal_db()
            journal_record = self._chain.record_journal()

            blocks_to_import = []
            for i in range(10):
                self._chain.create_and_sign_transaction_for_queue_block(
                    gas_price=0x01,
                    gas=0x0c3500,
                    to=RECEIVER.public_key.to_canonical_address(),
                    value=1,
                    data=b"",
                    v=0,
                    r=0,
                    s=0
                )

                block_to_import = self._chain.import_current_queue_block()
                blocks_to_import.append(block_to_import)

            self._chain.discard_journal(journal_record)
            self._chain.disable_journal_db()

            for block_to_import in blocks_to_import:
                self._event_bus.broadcast(
                    NewBlockEvent(block=cast(P2PBlock, block_to_import))
                )

            return []


    async def test(self):
        to_return = {}
        to_return['response'] = 'worked'
        return to_return


    #
    # Gets
    #


    @format_params(decode_hex)
    async def getReceivableTransactions(self, chain_address):
        # create new chain for all requests
        chain = self._chain_class(self._chain.db, wallet_address=chain_address)

        receivable_transactions = chain.create_receivable_transactions()
        receivable_transactions_dict = receive_transactions_to_dict(receivable_transactions, chain)

        return receivable_transactions_dict

    @format_params(decode_hex)
    async def getTransactionReceipt(self, tx_hash):
        chain = self._chain_class(self._chain.db, wallet_address = self._chain.wallet_address)
        receipt = chain.chaindb.get_transaction_receipt(tx_hash)

        receipt_dict = receipt_to_dict(receipt, tx_hash, chain)

        return receipt_dict

    async def getGasPrice(self):
        required_min_gas_price = self._chain.chaindb.get_required_block_min_gas_price()
        return hex(required_min_gas_price)

    async def getHistoricalGasPrice(self):

        historical_min_gas_price = self._chain.chaindb.load_historical_minimum_gas_price()

        encoded = []
        for timestamp_gas_price in historical_min_gas_price:
            encoded.append([hex(timestamp_gas_price[0]), hex(timestamp_gas_price[1])])

        return encoded


    @format_params(decode_hex)
    async def getBlockNumber(self, chain_address):
        chain = self._chain_class(self._chain.db, wallet_address=chain_address)
        canonical_header = chain.chaindb.get_canonical_head(chain_address)
        return hex(canonical_header.block_number)


    @format_params(decode_hex)
    async def getBlockCreationParams(self, chain_address):

        #create new chain for all requests
        chain = self._chain_class(self._chain.db, wallet_address = chain_address)

        to_return = {}

        to_return['block_number'] = hex(chain.header.block_number)
        to_return['parent_hash'] = encode_hex(chain.header.parent_hash)

        vm = chain.get_vm()

        to_return['nonce'] = hex(vm.state.account_db.get_nonce(chain_address))

        receivable_transactions = chain.create_receivable_transactions()
        encoded_receivable_transactions = []

        for re_tx in receivable_transactions:
            encoded_receivable_transactions.append(encode_hex(rlp.encode(re_tx)))

        to_return['receive_transactions'] = encoded_receivable_transactions

        reward_bundle = chain.consensus_db.create_reward_bundle_for_block(chain_address)
        amount = reward_bundle.reward_type_1.amount + reward_bundle.reward_type_2.amount
        print("SENDING BLOCK CREATION PARAMS REWARD BUNDLE WITH AMOUNT", amount)
        to_return['reward_bundle'] = encode_hex(rlp.encode(reward_bundle, sedes = StakeRewardBundle))

        return to_return


    @format_params(decode_hex, identity)
    async def getBlockByHash(self, block_hash: Hash32, include_transactions: bool = False):
        chain = self._chain_class(self._chain.db, wallet_address=self._chain.wallet_address)
        block = chain.get_block_by_hash(block_hash)
        return block_to_dict(block, include_transactions, chain)


    @format_params(to_int_if_hex, decode_hex, identity)
    async def getBlockByNumber(self, at_block, chain_address, include_transactions: bool = False):
        chain = self._chain_class(self._chain.db, wallet_address=chain_address)
        block = chain.get_block_by_number(at_block, chain_address=chain_address)
        return block_to_dict(block, include_transactions, chain)

    async def sendRawBlock(self, encoded_micro_block):
        chain = self._chain_class(self._chain.db, wallet_address=self._chain.wallet_address)

        encoded_micro_block = decode_hex(encoded_micro_block)

        micro_block = rlp.decode(encoded_micro_block, sedes=MicroBlock)

        block_class = self._chain_class.get_vm_class_for_block_timestamp().get_block_class()

        full_block = block_class.from_micro_block(micro_block)

        # Validate the block here
        if(full_block.header.timestamp < (int(time.time()) - MAX_ALLOWED_AGE_OF_NEW_RPC_BLOCK)):
            raise BaseRPCError("The block timestamp is to old. We can only import new blocks over RPC.")

        try:
            canonical_head = self._chain.chaindb.get_canonical_head(full_block.header.chain_address)
            if canonical_head.block_number >= full_block.header.block_number:
                raise BaseRPCError("You are attempting to replace an existing block. This is not allowed.")
        except CanonicalHeadNotFound:
            pass

        if((full_block.header.block_number != 0) and
            (not self._chain.chaindb.is_in_canonical_chain(full_block.header.parent_hash))):
            raise BaseRPCError("Parent block not found on canonical chain.")

        #Check our current syncing stage. Must be sync stage 4.
        current_sync_stage_response = await self._event_bus.request(
            CurrentSyncStageRequest()
        )
        if current_sync_stage_response.sync_stage < FULLY_SYNCED_STAGE_ID:
            raise BaseRPCError("This node is still syncing with the network. Please wait until this node has synced.")

        average_gas_price = get_block_average_transaction_gas_price(full_block)
        required_min_gas_price = self._chain.chaindb.get_required_block_min_gas_price(full_block.header.timestamp)

        if average_gas_price < required_min_gas_price:
            raise Exception("Block transactions don't meet the minimum gas price requirement of {}".format(required_min_gas_price))

        self._event_bus.broadcast(
            NewBlockEvent(block=cast(P2PBlock, full_block), from_rpc=True)
        )

        return True


    #
    # Admin tools and dev debugging
    #
    async def getChronologicalBlockWindowTimestampHashes(self, timestamp: Timestamp):
        chain = self._chain_class(self._chain.db, wallet_address=self._chain.wallet_address)
        chronological_block_window = chain.chain_head_db.load_chronological_block_window(timestamp)

        return [[timestamp_root_hash[0], encode_hex(timestamp_root_hash[1])] for timestamp_root_hash in chronological_block_window]

    async def getCurrentSyncingParameters(self):
        current_syncing_parameters_request = await self._event_bus.request(
            CurrentSyncingParametersRequest()
        )

        sync_parameters = current_syncing_parameters_request.current_syncing_parameters

        return sync_parameters.__dict__


    async def getBlockchainDBDetails(self):
        chain = self._chain_class(self._chain.db, wallet_address=self._chain.wallet_address)
        head_block_hashes = chain.chain_head_db.get_head_block_hashes()

        return [encode_hex(head_block_hash) for head_block_hash in head_block_hashes]

    async def getCurrentStakeFromBootnodeList(self):
        '''
        Returns the current list of node stakes that this node has already retrieved.
        For debugging purposes
        :return:
        '''
        stake_from_bootnode_response = await self._event_bus.request(
            StakeFromBootnodeRequest()
        )
        return [(encode_hex(address), stake) for address, stake in stake_from_bootnode_response.peer_stake_from_bootstrap_node.items()]

    async def getAccountBalances(self):
        chain = self._chain_class(self._chain.db, wallet_address=self._chain.wallet_address)
        next_head_hashes = chain.chain_head_db.get_head_block_hashes_list()

        wallet_addresses = []
        for next_head_hash in next_head_hashes:
            chain_address = chain.chaindb.get_chain_wallet_address_for_block_hash(next_head_hash)
            wallet_addresses.append(chain_address)

        out = {}
        for wallet_address in wallet_addresses:
            out[encode_hex(wallet_address)] = chain.get_vm().state.account_db.get_balance(wallet_address)

        return out

    async def getBlockchainDatabase(self):
        chain_object = self._chain_class(self._chain.db, wallet_address=self._chain.wallet_address)

        chain_head_hashes = chain_object.chain_head_db.get_head_block_hashes_list()

        chains_dict = []
        for head_hash in chain_head_hashes:
            chain = chain_object.get_all_blocks_on_chain_by_head_block_hash(head_hash)

            blocks_dict = []
            for block in chain:
                blocks_dict.append(block_to_dict(block, True, chain_object))

            chains_dict.append(blocks_dict)

        return chains_dict
