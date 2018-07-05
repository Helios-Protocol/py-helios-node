import functools
import itertools
import logging

from abc import (
    ABCMeta,
    abstractmethod
)
from typing import (
    cast,
    Dict,
    Iterable,
    List,
    Tuple,
    Type,
    TYPE_CHECKING,
    Union,
)


import rlp

from trie import (
    HexaryTrie,
)

from eth_typing import (
    BlockNumber,
    Hash32,
    Address
)

from eth_utils import (
    to_list,
    to_tuple,
)

from eth_hash.auto import keccak

from evm.constants import (
    GENESIS_PARENT_HASH,
    COIN_MATURE_TIME_FOR_STAKING,
)
from evm.exceptions import (
    CanonicalHeadNotFound,
    HeaderNotFound,
    ParentNotFound,
    TransactionNotFound,
)
from evm.db.backends.base import (
    BaseDB
)
from evm.db.schema import SchemaV1
from evm.rlp.headers import (
    BlockHeader,
)
from evm.rlp.receipts import (
    Receipt
)
from evm.utils.hexadecimal import (
    encode_hex,
)
from evm.validation import (
    validate_uint256,
    validate_word,
    validate_canonical_address,
)

from evm.rlp import sedes as evm_rlp_sedes
from evm.rlp.sedes import(
    trie_root,
    address,
    hash32
)

from evm.utils.rlp import make_mutable
if TYPE_CHECKING:
    from evm.rlp.blocks import (  # noqa: F401
        BaseBlock
    )
    from evm.rlp.transactions import (  # noqa: F401
        BaseTransaction,
        BaseReceiveTransaction
    )


class TransactionKey(rlp.Serializable):
    fields = [
        ('block_hash', hash32),
        ('index', rlp.sedes.big_endian_int),
        ('is_receive', rlp.sedes.boolean),
    ]


class BaseChainDB(metaclass=ABCMeta):
    db = None  # type: BaseDB

    @abstractmethod
    def __init__(self, db: BaseDB) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    #
    # Canonical Chain API
    #
    @abstractmethod
    def get_canonical_block_header_by_number(self, block_number: BlockNumber) -> BlockHeader:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_canonical_block_hash(self, block_number: BlockNumber) -> Hash32:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_canonical_head(self) -> BlockHeader:
        raise NotImplementedError("ChainDB classes must implement this method")

    #
    # Header API
    #
    @abstractmethod
    def header_exists(self, block_hash: Hash32) -> bool:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_block_header_by_hash(self, block_hash: Hash32) -> BlockHeader:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def persist_header(self, header: BlockHeader) -> Tuple[BlockHeader, ...]:
        raise NotImplementedError("ChainDB classes must implement this method")

    #
    # Block API
    #
    @abstractmethod
    def persist_block(self, block: 'BaseBlock') -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    #
    # Transaction API
    #
    @abstractmethod
    def add_receipt(self,
                    block_header: BlockHeader,
                    index_key: int, receipt: Receipt) -> Hash32:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def add_transaction(self,
                        block_header: BlockHeader,
                        index_key: int, transaction: 'BaseTransaction') -> Hash32:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_block_transactions(
            self,
            block_header: BlockHeader,
            transaction_class: Type['BaseTransaction']) -> Iterable['BaseTransaction']:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_block_transaction_hashes(self, block_header: BlockHeader) -> Iterable[Hash32]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_receipts(self,
                     header: BlockHeader,
                     receipt_class: Type[Receipt]) -> Iterable[Receipt]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_transaction_by_index(
            self,
            block_number: BlockNumber,
            transaction_index: int,
            transaction_class: Type['BaseTransaction']) -> 'BaseTransaction':
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_transaction_by_index_and_block_hash(
            self,
            block_hash: Hash32,
            transaction_index: int,
            transaction_class: Type['BaseTransaction']) -> 'BaseTransaction':
        raise NotImplementedError("ChainDB classes must implement this method")
        
    @abstractmethod
    def get_receive_transaction_by_index_and_block_hash(
            self,
            block_hash: Hash32,
            transaction_index: int,
            transaction_class: Type['BaseTransaction']) -> 'BaseTransaction':
        raise NotImplementedError("ChainDB classes must implement this method")


    @abstractmethod
    def get_transaction_index(self, transaction_hash: Hash32) -> Tuple[BlockNumber, int]:
        raise NotImplementedError("ChainDB classes must implement this method")

    #
    # Raw Database API
    #
    @abstractmethod
    def exists(self, key: bytes) -> bool:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def persist_trie_data_dict(self, trie_data_dict: Dict[bytes, bytes]) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")


class ChainDB(BaseChainDB):
    logger = logging.getLogger('evm.db.chain_head.ChainDB')
    
    def __init__(self, db: BaseDB, wallet_address:Address) -> None:
        self.db = db
        validate_canonical_address(wallet_address, "Wallet Address") 
        self.wallet_address = wallet_address

    #
    # Canonical Chain API
    #
    def get_canonical_block_hash(self, block_number: BlockNumber, wallet_address = None) -> Hash32:
        """
        Return the block hash for the given block number.
        """
        if wallet_address is None:
            wallet_address = self.wallet_address
        validate_uint256(block_number, title="Block Number")
        number_to_hash_key = SchemaV1.make_block_number_to_hash_lookup_key(wallet_address, block_number)
        try:
            return rlp.decode(
                self.db[number_to_hash_key],
                sedes=rlp.sedes.binary,
            )
        except KeyError:
            raise HeaderNotFound(
                "No header found on the canonical chain with number {0}".format(block_number)
            )

    def get_canonical_block_header_by_number(self, block_number: BlockNumber, wallet_address = None) -> BlockHeader:
        """
        Returns the block header with the given number in the canonical chain.

        Raises HeaderNotFound if there's no block header with the given number in the
        canonical chain.
        """
        if wallet_address is None:
            wallet_address = self.wallet_address
            
        validate_uint256(block_number, title="Block Number")
        return self.get_block_header_by_hash(self.get_canonical_block_hash(block_number, wallet_address))

    def get_canonical_head(self, wallet_address = None) -> BlockHeader:
        """
        Returns the current block header at the head of the chain.

        Raises CanonicalHeadNotFound if no canonical head has been set.
        """
        if wallet_address is None:
            wallet_address = self.wallet_address
        try:
            canonical_head_hash = self.db[SchemaV1.make_canonical_head_hash_lookup_key(wallet_address)]
        except KeyError:
            raise CanonicalHeadNotFound("No canonical head set for this chain")
        return self.get_block_header_by_hash(
            cast(Hash32, canonical_head_hash),
        )
        
    def get_block_by_hash(self, block_hash, block_class):
        
        block_header = self.get_block_header_by_hash(block_hash)
        
        send_transactions = self.get_block_transactions(block_header, block_class.transaction_class)
        
        receive_transactions = self.get_block_receive_transactions(block_header, block_class.receive_transaction_class)
        
        output_block = block_class(block_header, send_transactions, receive_transactions)
        
        return output_block
    
    def get_block_by_number(self, block_number, block_class, wallet_address = None):
        if wallet_address is None:
            wallet_address = self.wallet_address
        
        block_header = self.get_canonical_block_header_by_number(block_number, wallet_address)
        
        send_transactions = self.get_block_transactions(block_header, block_class.transaction_class)
        
        receive_transactions = self.get_block_receive_transactions(block_header, block_class.receive_transaction_class)
        
        output_block = block_class(block_header, send_transactions, receive_transactions)
        
        return output_block
        
        
    def get_all_blocks_on_chain(self, block_class, wallet_address = None):
        if wallet_address is None:
            wallet_address = self.wallet_address
            
        canonical_head_header = self.get_canonical_head(wallet_address = wallet_address)
        chain_length = canonical_head_header.block_number + 1
        
        blocks = []
        for block_number in range(chain_length):
            blocks.append(self.get_block_by_number(block_number, block_class, wallet_address))
        
        return blocks
        
        
    #
    # Header API
    #
    def header_exists(self, block_hash: Hash32) -> bool:
        """
        Returns True if the header with the given hash is in our DB.
        """
        return self.db.exists(block_hash)

    def get_block_header_by_hash(self, block_hash: Hash32) -> BlockHeader:
        """
        Returns the requested block header as specified by block hash.

        Raises HeaderNotFound if it is not present in the db.
        """
        validate_word(block_hash, title="Block Hash")
        try:
            header_rlp = self.db[block_hash]
        except KeyError:
            raise HeaderNotFound(
                "No header with hash {0} found".format(encode_hex(block_hash))
            )
        return _decode_block_header(header_rlp)


    # TODO: This method should take a chain of headers as that's the most common use case
    # and it'd be much faster than inserting each header individually.
    def persist_header(self, header: BlockHeader) -> Tuple[BlockHeader, ...]:
        """
        Returns iterable of headers newly on the canonical chain
        """
        is_genesis = header.parent_hash == GENESIS_PARENT_HASH
        if not is_genesis and not self.header_exists(header.parent_hash):
            raise ParentNotFound(
                "Cannot persist block header ({}) with unknown parent ({})".format(
                    encode_hex(header.hash), encode_hex(header.parent_hash)))
        
        self.db.set(
            header.hash,
            rlp.encode(header),
        )
        
        #save the block to the chain wallet address lookup db
        self.save_block_hash_to_chain_wallet_address(header.hash)

        try:
            head_block_number = self.get_canonical_head().block_number
        except CanonicalHeadNotFound:
            new_headers = self._set_as_canonical_chain_head(header)
        else:
            if header.block_number > head_block_number:
                new_headers = self._set_as_canonical_chain_head(header)
            else:
                new_headers = tuple()

        return new_headers
    

        
    # TODO: update this to take a `hash` rather than a full header object.
    def _set_as_canonical_chain_head(self, header: BlockHeader) -> Tuple[BlockHeader, ...]:
        """
        Returns iterable of headers newly on the canonical head
        """
        try:
            self.get_block_header_by_hash(header.hash)
        except HeaderNotFound:
            raise ValueError("Cannot use unknown block hash as canonical head: {}".format(
                header.hash))

        new_canonical_headers = tuple(reversed(self._find_new_ancestors(header)))

        # remove transaction lookups for blocks that are no longer canonical
        for h in new_canonical_headers:
            try:
                old_hash = self.get_canonical_block_hash(h.block_number)
            except HeaderNotFound:
                # no old block, and no more possible
                break
            else:
                old_header = self.get_block_header_by_hash(old_hash)
                for transaction_hash in self.get_block_transaction_hashes(old_header):
                    self._remove_transaction_from_canonical_chain(transaction_hash)
                    # TODO re-add txn to internal pending pool (only if local sender)
                    pass

        for h in new_canonical_headers:
            self._add_block_number_to_hash_lookup(h)

        self.db.set(SchemaV1.make_canonical_head_hash_lookup_key(self.wallet_address), header.hash)

        return new_canonical_headers

    @to_tuple
    def _find_new_ancestors(self, header: BlockHeader) -> Iterable[BlockHeader]:
        """
        Returns the chain leading up from the given header until (but not including)
        the first ancestor it has in common with our canonical chain.

        If D is the canonical head in the following chain, and F is the new header,
        then this function returns (F, E).

        A - B - C - D
               \
                E - F
        """
        h = header
        while True:
            try:
                orig = self.get_canonical_block_header_by_number(h.block_number)
            except HeaderNotFound:
                # This just means the block is not on the canonical chain.
                pass
            else:
                if orig.hash == h.hash:
                    # Found the common ancestor, stop.
                    break

            # Found a new ancestor
            yield h

            if h.parent_hash == GENESIS_PARENT_HASH:
                break
            else:
                h = self.get_block_header_by_hash(h.parent_hash)

    def _add_block_number_to_hash_lookup(self, header: BlockHeader) -> None:
        """
        Sets a record in the database to allow looking up this header by its
        block number.
        """
        block_number_to_hash_key = SchemaV1.make_block_number_to_hash_lookup_key(
            self.wallet_address,
            header.block_number
        )
        self.db.set(
            block_number_to_hash_key,
            rlp.encode(header.hash, sedes=rlp.sedes.binary),
        )

    
    #
    # Block API
    #
    
    @classmethod
    def get_chain_wallet_address_for_block_hash(cls, db, block_hash):
        block_hash_save_key = SchemaV1.make_block_hash_to_chain_wallet_address_lookup_key(block_hash)
        try:
            return db[block_hash_save_key]
        except KeyError:
            raise ValueError("Block hash {} not found in database".format(block_hash))
        
    def save_block_hash_to_chain_wallet_address(self, block_hash, wallet_address = None):
        if wallet_address is None:
            wallet_address = self.wallet_address
        block_hash_save_key = SchemaV1.make_block_hash_to_chain_wallet_address_lookup_key(block_hash)
        self.db[block_hash_save_key] = wallet_address
        
    def persist_block(self, block: 'BaseBlock') -> None:
        '''
        Persist the given block's header and uncles.

        Assumes all block transactions have been persisted already.
        '''
        new_canonical_headers = self.persist_header(block.header)
        
        

        for header in new_canonical_headers:
            for index, transaction_hash in enumerate(self.get_block_transaction_hashes(header)):
                self._add_transaction_to_canonical_chain(transaction_hash, header, index)
            for index, transaction_hash in enumerate(self.get_block_receive_transaction_hashes(header)):
                self._add_receive_transaction_to_canonical_chain(transaction_hash, header, index)
            
            #add all receive transactions as children to the sender block
            self.add_block_receive_transactions_to_parent_child_lookup(header, block.receive_transaction_class)
        
        #we also have to save this block as the child of the parent block in the same chain
        if block.header.parent_hash != GENESIS_PARENT_HASH:
            self.add_block_child(block.header.parent_hash, block.header.hash)

    
    #
    # Unprocessed Block API
    #
    def save_block_as_unprocessed(self, block):
        '''
        This saves the block as unprocessed, and saves to any unprocessed parents, including the one on this own chain and from receive transactions
        '''
        self.save_unprocessed_block_lookup(block.hash)
        if not self.is_block_processed(block.header.parent_hash):
            self.save_unprocessed_children_block_lookup(block.header.parent_hash)
        self.save_unprocessed_children_block_lookup_to_transaction_parents(block.header, block.receive_transaction_class)
        
    
    def save_block_as_processed(self, block):
        '''
        This removes any unprocessed lookups for this block.
        '''
        self.delete_unprocessed_block_lookup(block.hash)
        self.delete_unprocessed_children_blocks_lookup(block.hash)
        
        
    def save_unprocessed_block_lookup(self, block_hash):
        lookup_key = SchemaV1.make_unprocessed_block_lookup_key(block_hash)
        self.db[lookup_key] = b'1'
    
    def save_unprocessed_children_block_lookup(self, block_hash):
        lookup_key = SchemaV1.make_has_unprocessed_block_children_lookup_key(block_hash)
        self.db[lookup_key] = b'1'
        
        #need to also save for all receive transaction parents
        
    def save_unprocessed_children_block_lookup_to_transaction_parents(self, block_header, transaction_class):
        block_receive_transactions = self.get_block_receive_transactions(block_header,
                                                                        transaction_class)
        
        for receive_transaction in block_receive_transactions:
            if not self.is_block_processed(receive_transaction.sender_block_hash):
                self.save_unprocessed_children_block_lookup(receive_transaction.sender_block_hash)
            

        
    def has_unprocessed_children(self, block_hash):
        '''
        Returns True if the block has unprocessed children
        '''
        lookup_key = SchemaV1.make_has_unprocessed_block_children_lookup_key(block_hash)
        try:
            self.db[lookup_key]
            return True
        except KeyError:
            return False
    
    def is_block_processed(self, block_hash):
        '''
        Returns True if the block is processed
        '''
        lookup_key = SchemaV1.make_unprocessed_block_lookup_key(block_hash)
        try:
            self.db[lookup_key]
            return False
        except KeyError:
            return True
        
    
        
    def delete_unprocessed_block_lookup(self, block_hash):
        lookup_key = SchemaV1.make_unprocessed_block_lookup_key(block_hash)
        try:
            del(self.db[lookup_key])
        except KeyError:
            pass
        
    def delete_unprocessed_children_blocks_lookup(self, block_hash):
        lookup_key = SchemaV1.make_has_unprocessed_block_children_lookup_key(block_hash)
        try:
            del(self.db[lookup_key])
        except KeyError:
            pass
        
        
        
        
    #
    # Transaction API
    #
    def add_receipt(self, block_header: BlockHeader, index_key: int, receipt: Receipt) -> Hash32:
        """
        Adds the given receipt to the provide block header.

        Returns the updated `receipts_root` for updated block header.
        """
        receipt_db = HexaryTrie(db=self.db, root_hash=block_header.receipt_root)
        receipt_db[index_key] = rlp.encode(receipt)
        return receipt_db.root_hash

    def add_transaction(self,
                        block_header: BlockHeader,
                        index_key: int,
                        transaction: 'BaseTransaction') -> Hash32:
        """
        Adds the given transaction to the provide block header.

        Returns the updated `transactions_root` for updated block header.
        """

        transaction_db = HexaryTrie(self.db, root_hash=block_header.transaction_root)
        transaction_db[index_key] = rlp.encode(transaction)
        return transaction_db.root_hash
    
    def add_receive_transaction(self,
                        block_header: BlockHeader,
                        index_key: int,
                        transaction: 'BaseReceiveTransaction') -> Hash32:
        """
        Adds the given transaction to the provide block header.

        Returns the updated `transactions_root` for updated block header.
        """

        transaction_db = HexaryTrie(self.db, root_hash=block_header.receive_transaction_root)
        transaction_db[index_key] = rlp.encode(transaction)
        return transaction_db.root_hash

    def get_block_transactions(
            self,
            header: BlockHeader,
            transaction_class: 'BaseTransaction') -> Iterable['BaseTransaction']:
        """
        Returns an iterable of transactions for the block speficied by the
        given block header.
        """
            
        return self._get_block_transactions(header.transaction_root, transaction_class)
    
    def get_block_receive_transactions(
            self,
            header: BlockHeader,
            transaction_class: 'BaseReceiveTransaction') -> Iterable['BaseReceiveTransaction']:
        """
        Returns an iterable of transactions for the block speficied by the
        given block header.
        """
            
        return self._get_block_transactions(header.receive_transaction_root, transaction_class)

    @to_list
    def get_block_transaction_hashes(self, block_header: BlockHeader) -> Iterable[Hash32]:
        """
        Returns an iterable of the transaction hashes from th block specified
        by the given block header.
        """
        all_encoded_transactions = self._get_block_transaction_data(
            block_header.transaction_root,
        )
        for encoded_transaction in all_encoded_transactions:
            yield keccak(encoded_transaction)
            
    @to_list
    def get_block_receive_transaction_hashes(self, block_header: BlockHeader) -> Iterable[Hash32]:
        """
        Returns an iterable of the transaction hashes from th block specified
        by the given block header.
        """
        all_encoded_transactions = self._get_block_transaction_data(
            block_header.receive_transaction_root,
        )
        for encoded_transaction in all_encoded_transactions:
            yield keccak(encoded_transaction)

    @to_tuple
    def get_receipts(self,
                     header: BlockHeader,
                     receipt_class: Type[Receipt]) -> Iterable[Receipt]:
        """
        Returns an iterable of receipts for the block specified by the given
        block header.
        """
        receipt_db = HexaryTrie(db=self.db, root_hash=header.receipt_root)
        for receipt_idx in itertools.count():
            receipt_key = rlp.encode(receipt_idx)
            if receipt_key in receipt_db:
                receipt_data = receipt_db[receipt_key]
                yield rlp.decode(receipt_data, sedes=receipt_class)
            else:
                break

    def get_transaction_by_index(
            self,
            block_number: BlockNumber,
            transaction_index: int,
            transaction_class: Type['BaseTransaction']) -> 'BaseTransaction':
        """
        Returns the transaction at the specified `transaction_index` from the
        block specified by `block_number` from the canonical chain.

        Raises TransactionNotFound if no block
        """
        try:
            block_header = self.get_canonical_block_header_by_number(block_number)
        except HeaderNotFound:
            raise TransactionNotFound("Block {} is not in the canonical chain".format(block_number))
        transaction_db = HexaryTrie(self.db, root_hash=block_header.transaction_root)
        encoded_index = rlp.encode(transaction_index)
        if encoded_index in transaction_db:
            encoded_transaction = transaction_db[encoded_index]
            return rlp.decode(encoded_transaction, sedes=transaction_class)
        else:
            raise TransactionNotFound(
                "No transaction is at index {} of block {}".format(transaction_index, block_number))
            
    def get_transaction_by_index_and_block_hash(
            self,
            block_hash: Hash32,
            transaction_index: int,
            transaction_class: Type['BaseTransaction']) -> 'BaseTransaction':
        """
        Returns the transaction at the specified `transaction_index` from the
        block specified by `block_number` from the canonical chain.

        Raises TransactionNotFound if no block
        """
        try:
            block_header = self.get_block_header_by_hash(block_hash)
        except HeaderNotFound:
            raise TransactionNotFound("Block {} is not in the canonical chain".format(block_hash))
        transaction_db = HexaryTrie(self.db, root_hash=block_header.transaction_root)
        encoded_index = rlp.encode(transaction_index)
        if encoded_index in transaction_db:
            encoded_transaction = transaction_db[encoded_index]
            return rlp.decode(encoded_transaction, sedes=transaction_class)
        else:
            raise TransactionNotFound(
                "No transaction is at index {} of block {}".format(transaction_index, block_number))
            
    def get_receive_transaction_by_index_and_block_hash(
            self,
            block_hash: Hash32,
            transaction_index: int,
            transaction_class: Type['BaseTransaction']) -> 'BaseTransaction':
        """
        Returns the transaction at the specified `transaction_index` from the
        block specified by `block_number` from the canonical chain.

        Raises TransactionNotFound if no block
        """
        try:
            block_header = self.get_block_header_by_hash(block_hash)
        except HeaderNotFound:
            raise TransactionNotFound("Block {} is not in the canonical chain".format(block_hash))
        transaction_db = HexaryTrie(self.db, root_hash=block_header.receive_transaction_root)
        encoded_index = rlp.encode(transaction_index)
        if encoded_index in transaction_db:
            encoded_transaction = transaction_db[encoded_index]
            return rlp.decode(encoded_transaction, sedes=transaction_class)
        else:
            raise TransactionNotFound(
                "No transaction is at index {} of block {}".format(transaction_index, block_number))
            
    def get_receive_transaction_by_index(
            self,
            block_number: BlockNumber,
            transaction_index: int,
            transaction_class: 'BaseReceiveTransaction') -> 'BaseReceiveTransaction':
        """
        Returns the transaction at the specified `transaction_index` from the
        block specified by `block_number` from the canonical chain.

        Raises TransactionNotFound if no block
        """
        try:
            block_header = self.get_canonical_block_header_by_number(block_number)
        except HeaderNotFound:
            raise TransactionNotFound("Block {} is not in the canonical chain".format(block_number))
        transaction_db = HexaryTrie(self.db, root_hash=block_header.receive_transaction_root)
        encoded_index = rlp.encode(transaction_index)
        if encoded_index in transaction_db:
            encoded_transaction = transaction_db[encoded_index]
            return rlp.decode(encoded_transaction, sedes=transaction_class)
        else:
            raise TransactionNotFound(
                "No transaction is at index {} of block {}".format(transaction_index, block_number))

    def get_transaction_index(self, transaction_hash: Hash32) -> Tuple[BlockNumber, int]:
        """
        Returns a 2-tuple of (block_number, transaction_index) indicating which
        block the given transaction can be found in and at what index in the
        block transactions.

        Raises TransactionNotFound if the transaction_hash is not found in the
        canonical chain.
        """
        key = SchemaV1.make_transaction_hash_to_block_lookup_key(transaction_hash)
        try:
            encoded_key = self.db[key]
        except KeyError:
            raise TransactionNotFound(
                "Transaction {} not found in canonical chain".format(encode_hex(transaction_hash)))

        transaction_key = rlp.decode(encoded_key, sedes=TransactionKey)
        return (transaction_key.block_hash, transaction_key.index, transaction_key.is_receive)

    def _get_block_transaction_data(self, transaction_root: Hash32) -> Iterable[Hash32]:
        '''
        Returns iterable of the encoded transactions for the given block header
        '''
        transaction_db = HexaryTrie(self.db, root_hash=transaction_root)
        for transaction_idx in itertools.count():
            transaction_key = rlp.encode(transaction_idx)
            if transaction_key in transaction_db:
                yield transaction_db[transaction_key]
            else:
                break

    @functools.lru_cache(maxsize=32)
    @to_list
    def _get_block_transactions(
            self,
            transaction_root: Hash32,
            transaction_class: Union['BaseTransaction', 'BaseReceiveTransaction']) -> Iterable[Union['BaseTransaction', 'BaseReceiveTransaction']]:
        """
        Memoizable version of `get_block_transactions`
        """

        for encoded_transaction in self._get_block_transaction_data(transaction_root):
            yield rlp.decode(encoded_transaction, sedes=transaction_class)

    def _remove_transaction_from_canonical_chain(self, transaction_hash: Hash32) -> None:
        """
        Removes the transaction specified by the given hash from the canonical
        chain.
        """
        self.db.delete(SchemaV1.make_transaction_hash_to_block_lookup_key(transaction_hash))

    def _add_transaction_to_canonical_chain(self,
                                            transaction_hash: Hash32,
                                            block_header: BlockHeader,
                                            index: int
                                            ) -> None:
        """
        :param bytes transaction_hash: the hash of the transaction to add the lookup for
        :param block_header: The header of the block with the txn that is in the canonical chain
        :param int index: the position of the transaction in the block
        - add lookup from transaction hash to the block number and index that the body is stored at
        - remove transaction hash to body lookup in the pending pool
        """
        #TODO: allow this for contract addresses
        if block_header.sender != self.wallet_address:
            raise ValueError("Cannot add transaction to canonical chain because it is from a block on a different chain")
        transaction_key = TransactionKey(block_header.hash, index, False)
        self.db.set(
            SchemaV1.make_transaction_hash_to_block_lookup_key(transaction_hash),
            rlp.encode(transaction_key),
        )
        
    def _add_receive_transaction_to_canonical_chain(self,
                                            transaction_hash: Hash32,
                                            block_header: BlockHeader,
                                            index: int
                                            ) -> None:
        """
        :param bytes transaction_hash: the hash of the transaction to add the lookup for
        :param block_header: The header of the block with the txn that is in the canonical chain
        :param int index: the position of the transaction in the block
        - add lookup from transaction hash to the block number and index that the body is stored at
        - remove transaction hash to body lookup in the pending pool
        """
        #TODO: allow this for contract addresses
        if block_header.sender != self.wallet_address:
            raise ValueError("Cannot add transaction to canonical chain because it is from a block on a different chain")
        transaction_key = TransactionKey(block_header.hash, index, True)
        self.db.set(
            SchemaV1.make_transaction_hash_to_block_lookup_key(transaction_hash),
            rlp.encode(transaction_key),
        )


    #
    # Block children and Stake API
    #
    def add_block_receive_transactions_to_parent_child_lookup(self, block_header, transaction_class):
        block_receive_transactions = self.get_block_receive_transactions(block_header,
                                                                        transaction_class)
        
        for receive_transaction in block_receive_transactions:
            self.add_block_child(
                       receive_transaction.sender_block_hash,
                       block_header.hash)
            
        
    def remove_block_child(self,
                       parent_block_hash: Hash32,
                       child_block_hash: Hash32):
        
        validate_word(parent_block_hash, title="Block_hash")
        validate_word(child_block_hash, title="Block_hash")
        
        block_children = self.get_block_children(parent_block_hash)
        
        if block_children is None or child_block_hash not in block_children:
            self.logger.debug("tried to remove a block child that doesnt exist")
        else:
            block_children = make_mutable(block_children)
            block_children.remove(child_block_hash)
            self.save_block_children(parent_block_hash, block_children)

    
    def add_block_child(self,
                       parent_block_hash: Hash32,
                       child_block_hash: Hash32):
        validate_word(parent_block_hash, title="Block_hash")
        validate_word(child_block_hash, title="Block_hash")
        
        block_children = self.get_block_children(parent_block_hash)
        
        
        if block_children is None:
            self.save_block_children(parent_block_hash, [child_block_hash])
        elif child_block_hash in block_children:
            self.logger.debug("tried adding a child block that was already added")
        else:
            block_children = make_mutable(block_children)
            block_children.append(child_block_hash)
            self.save_block_children(parent_block_hash, block_children)
    
    def get_block_children(self, parent_block_hash: Hash32):
        validate_word(parent_block_hash, title="Block_hash")
        block_children_lookup_key = SchemaV1.make_block_children_lookup_key(parent_block_hash)
        try:
            return rlp.decode(self.db[block_children_lookup_key], sedes=rlp.sedes.CountableList(hash32))
        except KeyError:
            return None
        
    def save_block_children(self, parent_block_hash: Hash32,
                            block_children):
        
        validate_word(parent_block_hash, title="Block_hash")
        block_children_lookup_key = SchemaV1.make_block_children_lookup_key(parent_block_hash)
        self.db[block_children_lookup_key] = rlp.encode(block_children, sedes=rlp.sedes.CountableList(hash32))
        
    #we don't want to count the stake from the origin wallet address. This could allow 51% attacks.The origin chain shouldn't count becuase it is the chain with the conflict.
    def get_block_children_chains(self, block_hash, exclude_chains = None):
        origin_wallet_address = self.get_chain_wallet_address_for_block_hash(self.db, block_hash)
        child_chains = self._get_block_children_chains(block_hash)
        try:
            child_chains.remove(origin_wallet_address)
        except KeyError:
            pass
        if exclude_chains is not None:
            for wallet_address in exclude_chains:
                try:
                    child_chains.remove(wallet_address)
                except KeyError:
                    pass
        return list(child_chains)
    
    def _get_block_children_chains(self, block_hash):
        validate_word(block_hash, title="Block_hash")
        
        #lookup children
        children = self.get_block_children(block_hash)
        
        if children == None:
            return None
        else:
            child_chains = set()
            for child_block_hash in children:
                chain_wallet_address = self.get_chain_wallet_address_for_block_hash(self.db, child_block_hash)
                child_chains.add(chain_wallet_address)
                
                sub_children_chain_wallet_addresses = self._get_block_children_chains(child_block_hash)
                
                if sub_children_chain_wallet_addresses is not None:
                    child_chains.update(sub_children_chain_wallet_addresses)
            return child_chains
        
        
    #
    # Raw Database API
    #
    
    def exists(self, key: bytes) -> bool:
        """
        Returns True if the given key exists in the database.
        """
        return self.db.exists(key)

    def persist_trie_data_dict(self, trie_data_dict: Dict[bytes, bytes]) -> None:
        """
        Store raw trie data to db from a dict
        """
        for key, value in trie_data_dict.items():
            self.db[key] = value


# When performing a chain sync (either fast or regular modes), we'll very often need to look
# up recent block headers to validate the chain, and decoding their RLP representation is
# relatively expensive so we cache that here, but use a small cache because we *should* only
# be looking up recent blocks.
@functools.lru_cache(128)
def _decode_block_header(header_rlp: bytes) -> BlockHeader:
    return rlp.decode(header_rlp, sedes=BlockHeader)


class AsyncChainDB(ChainDB):

    async def coro_get_block_header_by_hash(self, block_hash: Hash32) -> BlockHeader:
        raise NotImplementedError()

    async def coro_get_canonical_head(self) -> BlockHeader:
        raise NotImplementedError()

    async def coro_header_exists(self, block_hash: Hash32) -> bool:
        raise NotImplementedError()

    async def coro_get_canonical_block_hash(self, block_number: BlockNumber) -> Hash32:
        raise NotImplementedError()

    async def coro_persist_header(self, header: BlockHeader) -> Tuple[BlockHeader, ...]:
        raise NotImplementedError()

    async def coro_persist_trie_data_dict(self, trie_data_dict: Dict[bytes, bytes]) -> None:
        raise NotImplementedError()
