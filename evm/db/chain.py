import functools
import itertools

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
    address
)
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
        ('wallet_address', address),
        ('block_number', rlp.sedes.big_endian_int),
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
    def __init__(self, db: BaseDB, wallet_address:Address) -> None:
        self.db = db
        validate_canonical_address(wallet_address, "Wallet Address") 
        self.wallet_address = wallet_address

    #
    # Canonical Chain API
    #
    def get_canonical_block_hash(self, block_number: BlockNumber) -> Hash32:
        """
        Return the block hash for the given block number.
        """
        validate_uint256(block_number, title="Block Number")
        number_to_hash_key = SchemaV1.make_block_number_to_hash_lookup_key(self.wallet_address, block_number)
        try:
            return rlp.decode(
                self.db[number_to_hash_key],
                sedes=rlp.sedes.binary,
            )
        except KeyError:
            raise HeaderNotFound(
                "No header found on the canonical chain with number {0}".format(block_number)
            )

    def get_canonical_block_header_by_number(self, block_number: BlockNumber) -> BlockHeader:
        """
        Returns the block header with the given number in the canonical chain.

        Raises HeaderNotFound if there's no block header with the given number in the
        canonical chain.
        """
        validate_uint256(block_number, title="Block Number")
        return self.get_block_header_by_hash(self.get_canonical_block_hash(block_number))

    def get_canonical_head(self) -> BlockHeader:
        """
        Returns the current block header at the head of the chain.

        Raises CanonicalHeadNotFound if no canonical head has been set.
        """
        try:
            canonical_head_hash = self.db[SchemaV1.make_canonical_head_hash_lookup_key(self.wallet_address)]
        except KeyError:
            raise CanonicalHeadNotFound("No canonical head set for this chain")
        return self.get_block_header_by_hash(
            cast(Hash32, canonical_head_hash),
        )
    
        
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

    #chronological head number is always 0   
#    def set_chronological_head_number(self, ch_head_number: ChBlockNumber) -> None:
#        """
#        sets the given chronological block number as chronological head
#        """
#        try:
#            self.get_block_hash_from_cronological_block_number(ch_head_number)
#        except ChronologicalBlockNumberNotFound:
#            raise ValueError("Cannot set chronological head for chronological block number that doesnt exist. chronological number: {}".format(ch_head_number))
#            
#            
#        chronological_head_number_key = SchemaV1.make_chronological_head_number_lookup_key()
#        self.db.set(
#            chronological_head_number_key,
#            rlp.encode(ch_head_number, sedes=rlp.sedes.big_endian_int),
#        )
        
#    def get_chronological_head_number(self) -> int:
#        """
#        gets the chronological head number
#        """
#        chronological_head_number_key = SchemaV1.make_chronological_head_number_lookup_key()
#        try:
#            return rlp.decode(self.db[chronological_head_number_key], rlp.sedes.big_endian_int)
#        except KeyError:
#            raise ValueError("No chronological head number found")
        
#    def add_block_hash_to_chronological_journal(self, block_hash: Hash32, is_genesis = False) -> None:
#        """
#        adds the block hash to the chronological journal, and sets it as new chronological head.
#        """
#        #first make sure the block exists
#        try:
#            self.get_block_header_by_hash(block_hash)
#        except HeaderNotFound:
#            raise ValueError("Cannot use unknown block hash as chronological head: {}".format(
#                block_hash))
#        
#        #get previous chronological head number
#        try:
#            chronological_head_number = self.get_chronological_head_number()
#        except ValueError:
#            new_chronological_head_number = 0
#        else:
#            #save this one as prev + 1
#            new_chronological_head_number = chronological_head_number + 1
#        
#        chronological_block_number_key = SchemaV1.make_chronological_block_number_lookup_key(
#            new_chronological_head_number
#        )
#        
#        self.db.set(
#            chronological_block_number_key,
#            rlp.encode(block_hash, sedes=evm_rlp_sedes.Hash32),
#        )
#        #lets also save the reverse lookup
#        block_hash_to_chronological_number_key = SchemaV1.make_block_hash_to_chronological_number_lookup_key(
#            block_hash
#        )
#        
#        self.db.set(
#            block_hash_to_chronological_number_key,
#            rlp.encode(new_chronological_head_number, sedes=rlp.sedes.big_endian_int),
#        )
#        
#        #finally save this one as the new chronological head
#        self.set_chronological_head_number(new_chronological_head_number)
#        
#    def get_chronological_block_number_from_block_hash(self, block_hash: Hash32) -> int:
#        """
#        gets the chronological block number for a given block hash
#        """
#        block_hash_to_chronological_number_key = SchemaV1.make_block_hash_to_chronological_number_lookup_key(
#            block_hash
#        )
#        try:
#            return rlp.decode(self.db[block_hash_to_chronological_number_key], sedes=rlp.sedes.big_endian_int)
#        except KeyError:
#            raise ValueError("Cannot find chronological block number for block hash: {}".format(
#                block_hash))
#        
#    def get_block_hash_from_cronological_block_number(self, ch_number: ChBlockNumber) -> Hash32:
#        """
#        gets the block hash for a given chronological block number
#        """
#        chronological_block_number_key = SchemaV1.make_chronological_block_number_lookup_key(
#            ch_number
#        )
#        try:
#            return rlp.decode(self.db[chronological_block_number_key], sedes=evm_rlp_sedes.Hash32)
#        except KeyError:
#            raise ChronologicalBlockNumberNotFound(
#                "Chronological block number {} not found".format(ch_number))
#        
#    

    
    #
    # Block API
    #
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
        return (transaction_key.wallet_address, transaction_key.block_number, transaction_key.index, transaction_key.is_receive)

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
        if block_header.sender != self.wallet_address:
            raise ValueError("Cannot add transaction to canonical chain because it is from a block on a different chain")
        transaction_key = TransactionKey(self.wallet_address, block_header.block_number, index, False)
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
        if block_header.sender != self.wallet_address:
            raise ValueError("Cannot add transaction to canonical chain because it is from a block on a different chain")
        transaction_key = TransactionKey(self.wallet_address, block_header.block_number, index, True)
        self.db.set(
            SchemaV1.make_transaction_hash_to_block_lookup_key(transaction_hash),
            rlp.encode(transaction_key),
        )

    
    #
    # State
    #
#    def get_state_root_from_block_hash(self, block_hash: Hash32) -> Hash32:
#        """
#        Retrieves the state root for a given block hash
#        """
#        try:
#            return rlp.decode(
#                self.db[SchemaV1.make_block_hash_to_state_root_lookup_key(block_hash)],
#                sedes=trie_root,
#            )
#        except KeyError:
#            raise HeaderToStateRootMapNotFound(
#                "No header->state_root map found"
#            )
#    
#    def set_block_hash_to_state_root_map(self, block_hash: Hash32, state_root, Hash32) -> None:
#        """
#        Saves the block hash -> state root lookup to database
#        """
#        self.db.set(
#            SchemaV1.make_block_hash_to_state_root_lookup_key(block_hash),
#            rlp.encode(state_root, sedes=trie_root),
#        )   
#    
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
