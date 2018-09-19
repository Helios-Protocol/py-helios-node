from cytoolz import (
    identity,
)

from eth_utils import (
    decode_hex,
    encode_hex,
    int_to_big_endian,
    is_integer,
)

from helios.rpc.format import (
    block_to_dict,
    header_to_dict,
    format_params,
    to_int_if_hex,
    transaction_to_dict,
)

from hp2p.chain import NewBlockQueueItem

# Tell mypy to ignore this import as a workaround for https://github.com/python/mypy/issues/4049
from helios.rpc.modules import (  # type: ignore
    RPCModule,
)


def get_header(chain, at_block):
    if at_block == 'pending':
        at_header = chain.header
    elif at_block == 'latest':
        at_header = chain.get_canonical_head()
    elif at_block == 'earliest':
        # TODO find if genesis block can be non-zero. Why does 'earliest' option even exist?
        at_header = chain.get_canonical_block_by_number(0).header
    elif is_integer(at_block) and at_block >= 0:
        at_header = chain.get_canonical_block_by_number(at_block).header
    else:
        raise TypeError("Unrecognized block reference: %r" % at_block)

    return at_header


def account_db_at_block(chain, at_block, read_only=True):
    at_header = get_header(chain, at_block)
    vm = chain.get_vm(at_header)
    return vm.state.account_db


def get_block_at_number(chain, at_block):
    if is_integer(at_block) and at_block >= 0:
        # optimization to avoid requesting block, then header, then block again
        return chain.get_canonical_block_by_number(at_block)
    else:
        at_header = get_header(chain, at_block)
        return chain.get_block_by_header(at_header)


class Hls(RPCModule):
    '''
    All the methods defined by JSON-RPC API, starting with "hls_"...

    Any attribute without an underscore is publicly accessible.
    '''

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
    def getBalance(self, address, at_block):
        account_db = account_db_at_block(self._chain, at_block)
        balance = account_db.get_balance(address)

        return hex(balance)

    @format_params(decode_hex, identity)
    def getBlockByHash(self, block_hash, include_transactions):
        block = self._chain.get_block_by_hash(block_hash)
        return block_to_dict(block, self._chain, include_transactions)

    @format_params(to_int_if_hex, identity)
    def getBlockByNumber(self, at_block, chain_address, include_transactions):
        block = get_block_at_number(self._chain, at_block)
        return block_to_dict(block, self._chain, include_transactions)

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
    
    def devAddValidNewBlock(self, version):
        if version == 1:
            '''
            import a valid block 
            '''
            from eth_keys import keys
            
            primary_private_keys = [b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5', b'\xa41\x95@\xbb\xa5\xde\xbbc\xffR\x8a\x18\x06\x95\xa3\xd7\xd2\x95]5{\x12\xe4n\xb6R\xd7S\x96\xf0+', b'\xd8>Fh\xefT\x04jf\x13\xca|E\xc4\x91\xed\x07\xcd\x02fW\xd8s;\xd8\xe4\xde\xb9\xbc\xe4\xf0I', b'\x83\x1d\xf6\xaf-\x00\xbfS4\x0f\xcds\x18"\xdd\x906]e\xfc\xe6\x0c?\xb1v20\xced7y\xf4', b")M\xf4\x1c\xb7\xe0Z\xf4\x17F\x9b\x089'\x004\xd3\x89\xd8\x80\xf5`\xa2\x11\x00\x90\xbd\x0f&KjZ", b'RI\xda\xbc7\xc4\xe8\tz\xfaI\x1f\xa1\x02{v\x0e\xac\x87W\xa2s\x81L4M\xad\xbd\xb3\x84\xaae', b'>kG\xd5\xb3qG\x84\xa6"\x1c~\xb6\xbf\x96\xac\n\x88\xfb\x05\x8aG\r\xe9Z\x16\x15\xb1P\xe0\xb7[', b'\x87\xf6\xb1\xa7v\x8bv<\xa3\xe5\xb18\xa7u\x99\xbaBa\xe9\xd5\x0e\xcb\x0f?\x84nZ\xba\xdf\xa3\x8a~', b'`$g\xe9\xa5r\xd2\xacG&\xf81^\x98\xf7\xda\xa5\xf4\x93)\xf3\x0c\x18\x84\xe4)!\x9dR\xa0\xac\xd3', b'\xcfd\xd5|\xe2\xf1\xda\xb9\x1f|\xb9\xdc\xeb \xd7\xb0\x81g\xdc\x03\xd6dQ\xf14\x19`\x94o\xf7\xc7\x1b', b'}LO\x14($d\n!\x1a\x91\xa8S\xb3\x05\xaa\x89\xf2\x0b\x97\xd3\x1c#\xe7\x86g`\xf1\x1a\xedXW']
            
            def get_primary_node_private_helios_key(instance_number = 0):
                return keys.PrivateKey(primary_private_keys[instance_number])
            
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
            self._chain.set_new_wallet_address(wallet_address = GENESIS_WALLET_ADDRESS, private_key = GENESIS_PRIVATE_KEY)
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
            try:
                chain_address = self._chain.chaindb.get_chain_wallet_address_for_block(block_to_import)
            except ValueError:
                return
            
            self._chain.discard_journal(journal_record)
            self._chain.disable_journal_db()
    
    
            syncer = self._p2p_server.syncer.chain_syncer

            block_queue_item = NewBlockQueueItem(new_block=block_to_import, chain_address=chain_address, from_rpc=True)

            syncer._new_blocks_to_import.put_nowait(block_queue_item)

            
        elif version == 2:
            '''
            import a valid block, but skips a block when sending out.
            '''
            from eth_keys import keys
            
            primary_private_keys = [b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5', b'\xa41\x95@\xbb\xa5\xde\xbbc\xffR\x8a\x18\x06\x95\xa3\xd7\xd2\x95]5{\x12\xe4n\xb6R\xd7S\x96\xf0+', b'\xd8>Fh\xefT\x04jf\x13\xca|E\xc4\x91\xed\x07\xcd\x02fW\xd8s;\xd8\xe4\xde\xb9\xbc\xe4\xf0I', b'\x83\x1d\xf6\xaf-\x00\xbfS4\x0f\xcds\x18"\xdd\x906]e\xfc\xe6\x0c?\xb1v20\xced7y\xf4', b")M\xf4\x1c\xb7\xe0Z\xf4\x17F\x9b\x089'\x004\xd3\x89\xd8\x80\xf5`\xa2\x11\x00\x90\xbd\x0f&KjZ", b'RI\xda\xbc7\xc4\xe8\tz\xfaI\x1f\xa1\x02{v\x0e\xac\x87W\xa2s\x81L4M\xad\xbd\xb3\x84\xaae', b'>kG\xd5\xb3qG\x84\xa6"\x1c~\xb6\xbf\x96\xac\n\x88\xfb\x05\x8aG\r\xe9Z\x16\x15\xb1P\xe0\xb7[', b'\x87\xf6\xb1\xa7v\x8bv<\xa3\xe5\xb18\xa7u\x99\xbaBa\xe9\xd5\x0e\xcb\x0f?\x84nZ\xba\xdf\xa3\x8a~', b'`$g\xe9\xa5r\xd2\xacG&\xf81^\x98\xf7\xda\xa5\xf4\x93)\xf3\x0c\x18\x84\xe4)!\x9dR\xa0\xac\xd3', b'\xcfd\xd5|\xe2\xf1\xda\xb9\x1f|\xb9\xdc\xeb \xd7\xb0\x81g\xdc\x03\xd6dQ\xf14\x19`\x94o\xf7\xc7\x1b', b'}LO\x14($d\n!\x1a\x91\xa8S\xb3\x05\xaa\x89\xf2\x0b\x97\xd3\x1c#\xe7\x86g`\xf1\x1a\xedXW']
            
            def get_primary_node_private_helios_key(instance_number = 0):
                return keys.PrivateKey(primary_private_keys[instance_number])
            
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
            self._chain.set_new_wallet_address(wallet_address = GENESIS_WALLET_ADDRESS, private_key = GENESIS_PRIVATE_KEY)
            
            
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
            
            
            
            self._chain.import_current_queue_block()

            self._chain.enable_journal_db()
            journal_record = self._chain.record_journal()
            
            self._chain.create_and_sign_transaction_for_queue_block(
                gas_price=0x01,
                gas=0x0c3500,
                to=RECEIVER.public_key.to_canonical_address(),
                value=3,
                data=b"",
                v=0,
                r=0,
                s=0
                )
            
            block_to_import = self._chain.import_current_queue_block()
            try:
                chain_address = self._chain.chaindb.get_chain_wallet_address_for_block(block_to_import)
            except ValueError:
                return
            
            self._chain.discard_journal(journal_record)
            self._chain.disable_journal_db()

            syncer = self._p2p_server.syncer.chain_syncer

            block_queue_item = NewBlockQueueItem(new_block=block_to_import, chain_address=chain_address, from_rpc=True)

            syncer._new_blocks_to_import.put_nowait(block_queue_item)

        elif version == 3:
            '''
            import a valid block that replaces an existing block. This is a valid conflict block. This peer will keep the original one
            '''
            from eth_keys import keys
            import time
            
            primary_private_keys = [b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5', b'\xa41\x95@\xbb\xa5\xde\xbbc\xffR\x8a\x18\x06\x95\xa3\xd7\xd2\x95]5{\x12\xe4n\xb6R\xd7S\x96\xf0+', b'\xd8>Fh\xefT\x04jf\x13\xca|E\xc4\x91\xed\x07\xcd\x02fW\xd8s;\xd8\xe4\xde\xb9\xbc\xe4\xf0I', b'\x83\x1d\xf6\xaf-\x00\xbfS4\x0f\xcds\x18"\xdd\x906]e\xfc\xe6\x0c?\xb1v20\xced7y\xf4', b")M\xf4\x1c\xb7\xe0Z\xf4\x17F\x9b\x089'\x004\xd3\x89\xd8\x80\xf5`\xa2\x11\x00\x90\xbd\x0f&KjZ", b'RI\xda\xbc7\xc4\xe8\tz\xfaI\x1f\xa1\x02{v\x0e\xac\x87W\xa2s\x81L4M\xad\xbd\xb3\x84\xaae', b'>kG\xd5\xb3qG\x84\xa6"\x1c~\xb6\xbf\x96\xac\n\x88\xfb\x05\x8aG\r\xe9Z\x16\x15\xb1P\xe0\xb7[', b'\x87\xf6\xb1\xa7v\x8bv<\xa3\xe5\xb18\xa7u\x99\xbaBa\xe9\xd5\x0e\xcb\x0f?\x84nZ\xba\xdf\xa3\x8a~', b'`$g\xe9\xa5r\xd2\xacG&\xf81^\x98\xf7\xda\xa5\xf4\x93)\xf3\x0c\x18\x84\xe4)!\x9dR\xa0\xac\xd3', b'\xcfd\xd5|\xe2\xf1\xda\xb9\x1f|\xb9\xdc\xeb \xd7\xb0\x81g\xdc\x03\xd6dQ\xf14\x19`\x94o\xf7\xc7\x1b', b'}LO\x14($d\n!\x1a\x91\xa8S\xb3\x05\xaa\x89\xf2\x0b\x97\xd3\x1c#\xe7\x86g`\xf1\x1a\xedXW']
            
            def get_primary_node_private_helios_key(instance_number = 0):
                return keys.PrivateKey(primary_private_keys[instance_number])
            
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
            self._chain.set_new_wallet_address(wallet_address = GENESIS_WALLET_ADDRESS, private_key = GENESIS_PRIVATE_KEY)
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
            try:
                chain_address = self._chain.chaindb.get_chain_wallet_address_for_block(block_to_import)
            except ValueError:
                return
            
            self._chain.discard_journal(journal_record)
            self._chain.disable_journal_db()
            
            self._chain.enable_journal_db()
            journal_record = self._chain.record_journal()
            
            self._chain.create_and_sign_transaction_for_queue_block(
                gas_price=0x01,
                gas=0x0c3500,
                to=RECEIVER.public_key.to_canonical_address(),
                value=2,
                data=b"",
                v=0,
                r=0,
                s=0
                )
            
            conflict_block_to_import = self._chain.import_current_queue_block()
            try:
                chain_address = self._chain.chaindb.get_chain_wallet_address_for_block(block_to_import)
            except ValueError:
                return
            
            self._chain.discard_journal(journal_record)
            self._chain.disable_journal_db()
            
    
    
            syncer = self._p2p_server.syncer.chain_syncer

            block_queue_item = NewBlockQueueItem(new_block=block_to_import, chain_address=chain_address, from_rpc=True)

            syncer._new_blocks_to_import.put_nowait(block_queue_item)
            
            #send the second conflicting block
            #time.sleep(1)
            
            syncer.propogate_block_to_network(conflict_block_to_import, chain_address)
            
        elif version == 4:
            '''
            import a valid block that replaces an existing block. This is a valid conflict block. This peer will actually have the second block. So the other peer will be forced to switch blocks.
            '''
            from eth_keys import keys
            import time
            
            primary_private_keys = [b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5', b'\xa41\x95@\xbb\xa5\xde\xbbc\xffR\x8a\x18\x06\x95\xa3\xd7\xd2\x95]5{\x12\xe4n\xb6R\xd7S\x96\xf0+', b'\xd8>Fh\xefT\x04jf\x13\xca|E\xc4\x91\xed\x07\xcd\x02fW\xd8s;\xd8\xe4\xde\xb9\xbc\xe4\xf0I', b'\x83\x1d\xf6\xaf-\x00\xbfS4\x0f\xcds\x18"\xdd\x906]e\xfc\xe6\x0c?\xb1v20\xced7y\xf4', b")M\xf4\x1c\xb7\xe0Z\xf4\x17F\x9b\x089'\x004\xd3\x89\xd8\x80\xf5`\xa2\x11\x00\x90\xbd\x0f&KjZ", b'RI\xda\xbc7\xc4\xe8\tz\xfaI\x1f\xa1\x02{v\x0e\xac\x87W\xa2s\x81L4M\xad\xbd\xb3\x84\xaae', b'>kG\xd5\xb3qG\x84\xa6"\x1c~\xb6\xbf\x96\xac\n\x88\xfb\x05\x8aG\r\xe9Z\x16\x15\xb1P\xe0\xb7[', b'\x87\xf6\xb1\xa7v\x8bv<\xa3\xe5\xb18\xa7u\x99\xbaBa\xe9\xd5\x0e\xcb\x0f?\x84nZ\xba\xdf\xa3\x8a~', b'`$g\xe9\xa5r\xd2\xacG&\xf81^\x98\xf7\xda\xa5\xf4\x93)\xf3\x0c\x18\x84\xe4)!\x9dR\xa0\xac\xd3', b'\xcfd\xd5|\xe2\xf1\xda\xb9\x1f|\xb9\xdc\xeb \xd7\xb0\x81g\xdc\x03\xd6dQ\xf14\x19`\x94o\xf7\xc7\x1b', b'}LO\x14($d\n!\x1a\x91\xa8S\xb3\x05\xaa\x89\xf2\x0b\x97\xd3\x1c#\xe7\x86g`\xf1\x1a\xedXW']
            
            def get_primary_node_private_helios_key(instance_number = 0):
                return keys.PrivateKey(primary_private_keys[instance_number])
            
            from hvm.chains.mainnet import (
                GENESIS_PRIVATE_KEY,
                GENESIS_WALLET_ADDRESS,
            )
            
            SENDER = GENESIS_PRIVATE_KEY
            RECEIVER = get_primary_node_private_helios_key(1)
            RECEIVER2 = get_primary_node_private_helios_key(2)
            RECEIVER3 = get_primary_node_private_helios_key(3)
            RECEIVER4 = get_primary_node_private_helios_key(4)
    
            chain_address = GENESIS_WALLET_ADDRESS
            
            #create tx and blocks from the genesis block.
            self._chain.set_new_wallet_address(wallet_address = GENESIS_WALLET_ADDRESS, private_key = GENESIS_PRIVATE_KEY)
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
            
            self._chain.enable_journal_db()
            journal_record = self._chain.record_journal()
            
            self._chain.create_and_sign_transaction_for_queue_block(
                gas_price=0x01,
                gas=0x0c3500,
                to=RECEIVER.public_key.to_canonical_address(),
                value=2,
                data=b"",
                v=0,
                r=0,
                s=0
                )
            
            conflict_block_to_import = self._chain.import_current_queue_block()

            self._chain.discard_journal(journal_record)
            self._chain.disable_journal_db()
            
    
    
            syncer = self._p2p_server.syncer.chain_syncer
            
            #send the conflict one first
            syncer.propogate_block_to_network(conflict_block_to_import, chain_address)
            
            #time.sleep(1)
            
            #then import the second one, so that we force the other peer to switch.
            block_queue_item = NewBlockQueueItem(new_block=block_to_import, chain_address=chain_address, from_rpc=True)

            syncer._new_blocks_to_import.put_nowait(block_queue_item)
            
            #send the second conflicting block
            
        elif version == 5:
            '''
            this one will send a whole bunch of the above ones.
            '''
            '''
                        import a valid block 
                        '''
            from eth_keys import keys

            primary_private_keys = [
                b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5',
                b'\xa41\x95@\xbb\xa5\xde\xbbc\xffR\x8a\x18\x06\x95\xa3\xd7\xd2\x95]5{\x12\xe4n\xb6R\xd7S\x96\xf0+',
                b'\xd8>Fh\xefT\x04jf\x13\xca|E\xc4\x91\xed\x07\xcd\x02fW\xd8s;\xd8\xe4\xde\xb9\xbc\xe4\xf0I',
                b'\x83\x1d\xf6\xaf-\x00\xbfS4\x0f\xcds\x18"\xdd\x906]e\xfc\xe6\x0c?\xb1v20\xced7y\xf4',
                b")M\xf4\x1c\xb7\xe0Z\xf4\x17F\x9b\x089'\x004\xd3\x89\xd8\x80\xf5`\xa2\x11\x00\x90\xbd\x0f&KjZ",
                b'RI\xda\xbc7\xc4\xe8\tz\xfaI\x1f\xa1\x02{v\x0e\xac\x87W\xa2s\x81L4M\xad\xbd\xb3\x84\xaae',
                b'>kG\xd5\xb3qG\x84\xa6"\x1c~\xb6\xbf\x96\xac\n\x88\xfb\x05\x8aG\r\xe9Z\x16\x15\xb1P\xe0\xb7[',
                b'\x87\xf6\xb1\xa7v\x8bv<\xa3\xe5\xb18\xa7u\x99\xbaBa\xe9\xd5\x0e\xcb\x0f?\x84nZ\xba\xdf\xa3\x8a~',
                b'`$g\xe9\xa5r\xd2\xacG&\xf81^\x98\xf7\xda\xa5\xf4\x93)\xf3\x0c\x18\x84\xe4)!\x9dR\xa0\xac\xd3',
                b'\xcfd\xd5|\xe2\xf1\xda\xb9\x1f|\xb9\xdc\xeb \xd7\xb0\x81g\xdc\x03\xd6dQ\xf14\x19`\x94o\xf7\xc7\x1b',
                b'}LO\x14($d\n!\x1a\x91\xa8S\xb3\x05\xaa\x89\xf2\x0b\x97\xd3\x1c#\xe7\x86g`\xf1\x1a\xedXW']

            def get_primary_node_private_helios_key(instance_number=0):
                return keys.PrivateKey(primary_private_keys[instance_number])

            from hvm.chains.mainnet import (
                GENESIS_PRIVATE_KEY,
                GENESIS_WALLET_ADDRESS,
            )

            SENDER = GENESIS_PRIVATE_KEY
            RECEIVER = get_primary_node_private_helios_key(1)
            RECEIVER2 = get_primary_node_private_helios_key(2)
            RECEIVER3 = get_primary_node_private_helios_key(3)
            RECEIVER4 = get_primary_node_private_helios_key(4)

            chain_address = GENESIS_WALLET_ADDRESS
            blocks_to_import = []
            # create tx and blocks from the genesis block.
            self._chain.set_new_wallet_address(wallet_address=GENESIS_WALLET_ADDRESS, private_key=GENESIS_PRIVATE_KEY)
            self._chain.reinitialize()
            self._chain.enable_journal_db()
            journal_record = self._chain.record_journal()

            for i in range(100):
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

                blocks_to_import.append(self._chain.import_current_queue_block())


            self._chain.discard_journal(journal_record)
            self._chain.disable_journal_db()

            syncer = self._p2p_server.syncer.chain_syncer

            count = 1
            for block_to_import in blocks_to_import:
                block_queue_item = NewBlockQueueItem(new_block=block_to_import, chain_address=chain_address, from_rpc=True)

                syncer._new_blocks_to_import.put_nowait(block_queue_item)


    def devAddInvalidNewBlock(self, version):
        if version == 1:
            '''
            import an invalid block
            '''
            from eth_keys import keys
            
            primary_private_keys = [b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5', b'\xa41\x95@\xbb\xa5\xde\xbbc\xffR\x8a\x18\x06\x95\xa3\xd7\xd2\x95]5{\x12\xe4n\xb6R\xd7S\x96\xf0+', b'\xd8>Fh\xefT\x04jf\x13\xca|E\xc4\x91\xed\x07\xcd\x02fW\xd8s;\xd8\xe4\xde\xb9\xbc\xe4\xf0I', b'\x83\x1d\xf6\xaf-\x00\xbfS4\x0f\xcds\x18"\xdd\x906]e\xfc\xe6\x0c?\xb1v20\xced7y\xf4', b")M\xf4\x1c\xb7\xe0Z\xf4\x17F\x9b\x089'\x004\xd3\x89\xd8\x80\xf5`\xa2\x11\x00\x90\xbd\x0f&KjZ", b'RI\xda\xbc7\xc4\xe8\tz\xfaI\x1f\xa1\x02{v\x0e\xac\x87W\xa2s\x81L4M\xad\xbd\xb3\x84\xaae', b'>kG\xd5\xb3qG\x84\xa6"\x1c~\xb6\xbf\x96\xac\n\x88\xfb\x05\x8aG\r\xe9Z\x16\x15\xb1P\xe0\xb7[', b'\x87\xf6\xb1\xa7v\x8bv<\xa3\xe5\xb18\xa7u\x99\xbaBa\xe9\xd5\x0e\xcb\x0f?\x84nZ\xba\xdf\xa3\x8a~', b'`$g\xe9\xa5r\xd2\xacG&\xf81^\x98\xf7\xda\xa5\xf4\x93)\xf3\x0c\x18\x84\xe4)!\x9dR\xa0\xac\xd3', b'\xcfd\xd5|\xe2\xf1\xda\xb9\x1f|\xb9\xdc\xeb \xd7\xb0\x81g\xdc\x03\xd6dQ\xf14\x19`\x94o\xf7\xc7\x1b', b'}LO\x14($d\n!\x1a\x91\xa8S\xb3\x05\xaa\x89\xf2\x0b\x97\xd3\x1c#\xe7\x86g`\xf1\x1a\xedXW']
            
            def get_primary_node_private_helios_key(instance_number = 0):
                return keys.PrivateKey(primary_private_keys[instance_number])
            
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
            self._chain.set_new_wallet_address(wallet_address = GENESIS_WALLET_ADDRESS, private_key = GENESIS_PRIVATE_KEY)
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
            try:
                chain_address = self._chain.chaindb.get_chain_wallet_address_for_block(block_to_import)
            except ValueError:
                return
            
            self._chain.discard_journal(journal_record)
            self._chain.disable_journal_db()
    
    
            syncer = self._p2p_server.syncer.chain_syncer
            
            rpc_message = {'block':block_to_import,
                           'chain_address':chain_address,}
            rpc_queue_item = ('new_block', rpc_message)
            syncer.rpc_queue.put_nowait(rpc_queue_item)



    def test(self):
        to_return = {}
        to_return['response'] = 'worked'
        return to_return

