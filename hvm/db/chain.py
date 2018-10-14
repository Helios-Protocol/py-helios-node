import functools
import itertools
import logging
import time
from uuid import UUID

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
    Optional,
)

from hvm.types import Timestamp

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

from hvm.constants import (
    GENESIS_PARENT_HASH,
    COIN_MATURE_TIME_FOR_STAKING,
    MIN_GAS_PRICE_CALCULATION_AVERAGE_DELAY,
    MIN_GAS_PRICE_CALCULATION_AVERAGE_WINDOW_LENGTH,
    MIN_GAS_PRICE_CALCULATION_MIN_TIME_BETWEEN_CHANGE_IN_MIN_GAS_PRICE,
    MAX_NUM_HISTORICAL_MIN_GAS_PRICE_TO_KEEP,
    ZERO_HASH32,
)
from hvm.exceptions import (
    CanonicalHeadNotFound,
    HeaderNotFound,
    ParentNotFound,
    TransactionNotFound,
    JournalDbNotActivated,
    HistoricalNetworkTPCMissing,
    HistoricalMinGasPriceError,
    NotEnoughDataForHistoricalMinGasPriceCalculation,
)
from hvm.db.backends.base import (
    BaseDB
)
from hvm.db.schema import SchemaV1
from hvm.rlp.headers import (
    BlockHeader,
)
from hvm.rlp.receipts import (
    Receipt
)
from hvm.utils.hexadecimal import (
    encode_hex,
)
from hvm.validation import (
    validate_uint256,
    validate_is_integer,
    validate_word,
    validate_canonical_address,
    validate_centisecond_timestamp,
    validate_is_bytes,
)

from hvm.rlp.consensus import StakeRewardBundle
from hvm.rlp import sedes as evm_rlp_sedes
from hvm.rlp.sedes import(
    trie_root,
    address,
    hash32,

)
from rlp.sedes import(
    big_endian_int,
    CountableList,
    binary,
)


from hvm.db.journal import (
    JournalDB,
)

from hvm.utils.rlp import make_mutable

from sortedcontainers import (
    SortedList,
    SortedDict,
)

from hvm.utils.numeric import (
    are_items_in_list_equal,
)

from hvm.utils.padding import de_sparse_timestamp_item_list
if TYPE_CHECKING:
    from hvm.rlp.blocks import (  # noqa: F401
        BaseBlock
    )
    from hvm.rlp.transactions import (  # noqa: F401
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
    def get_canonical_block_header_by_number(self, block_number: BlockNumber, wallet_address: Address = None) -> BlockHeader:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_canonical_block_hash(self, block_number: BlockNumber) -> Hash32:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_canonical_head(self, wallet_address: Optional[Address]) -> BlockHeader:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_canonical_head_hash(self, wallet_address: Address = None) -> Hash32:
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

    @abstractmethod
    def get_block_by_hash(self, block_hash: Hash32, block_class: type('BaseBlock')) -> 'BaseBlock':
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
    # Unprocessed block API
    #
    @abstractmethod
    def is_block_unprocessed(self, block_hash: Hash32) -> bool:
        raise NotImplementedError("ChainDB classes must implement this method")

    #
    # Staking and staking system related functions
    #
    @abstractmethod
    def get_block_number_of_latest_reward_block(self, wallet_address: Address = None) -> BlockNumber:
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
    logger = logging.getLogger('hvm.db.chain_db.ChainDB')
    _journaldb = None

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
            self.logger.debug
            raise HeaderNotFound(
                "No header found on the canonical chain {} with number {}".format(wallet_address, block_number)
            )

    def get_canonical_block_header_by_number(self, block_number: BlockNumber, wallet_address: Address = None) -> BlockHeader:
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
        canonical_head_hash = self.get_canonical_head_hash(wallet_address)
        return self.get_block_header_by_hash(
            cast(Hash32, canonical_head_hash),
        )

    def get_canonical_head_hash(self, wallet_address: Address = None) -> Hash32:
        if wallet_address is None:
            wallet_address = self.wallet_address
        try:
            return self.db[SchemaV1.make_canonical_head_hash_lookup_key(wallet_address)]
        except KeyError:
            raise CanonicalHeadNotFound("No canonical head set for this chain")

    def get_block_by_hash(self, block_hash: Hash32, block_class) -> 'BaseBlock':

        block_header = self.get_block_header_by_hash(block_hash)

        send_transactions = self.get_block_transactions(block_header, block_class.transaction_class)

        receive_transactions = self.get_block_receive_transactions(block_header, block_class.receive_transaction_class)

        reward_bundle = self.get_reward_bundle(block_header.reward_hash)

        output_block = block_class(block_header, send_transactions, receive_transactions, reward_bundle)

        return output_block

    def get_block_by_number(self, block_number: BlockNumber, block_class, wallet_address = None) -> 'BaseBlock':
        if wallet_address is None:
            wallet_address = self.wallet_address

        block_hash = self.get_canonical_block_hash(block_number, wallet_address)
        return self.get_block_by_hash(block_hash, block_class)



    def get_blocks_on_chain(self, block_class,  start, end, wallet_address = None):
        if wallet_address is None:
            wallet_address = self.wallet_address

        blocks = []
        for block_number in range(start, end+1):
            try:
                new_block = self.get_block_by_number(block_number, block_class, wallet_address)
                blocks.append(new_block)
            except HeaderNotFound:
                break

        return blocks

    def get_all_blocks_on_chain(self, block_class, wallet_address = None):
        if wallet_address is None:
            wallet_address = self.wallet_address

        canonical_head_header = self.get_canonical_head(wallet_address = wallet_address)
        head_block_number = canonical_head_header.block_number


        return self.get_blocks_on_chain(block_class,  0, head_block_number, wallet_address = wallet_address)


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

        self.save_header_to_db(header)

        #save the block to the chain wallet address lookup db
        #this is so we can lookup which chain the block belongs to.
        self.save_block_hash_to_chain_wallet_address(header.hash)

        try:
            head_block_number = self.get_canonical_head().block_number
        except CanonicalHeadNotFound:
            new_headers = self._set_as_canonical_chain_head(header)
        else:
            new_headers = self._set_as_canonical_chain_head(header)

        return new_headers



    def save_header_to_db(self, header: BlockHeader):
        self.db.set(
            header.hash,
            rlp.encode(header),
        )


    def delete_canonical_chain(self, wallet_address = None):
        if wallet_address is None:
            wallet_address = self.wallet_address

        try:
            canonical_header = self.get_canonical_head(wallet_address = wallet_address)
        except CanonicalHeadNotFound:
            canonical_header = None

        if canonical_header is not None:
            for i in range(0, canonical_header.block_number+1):
                header_to_remove = self.get_canonical_block_header_by_number(i, wallet_address = wallet_address)
                for transaction_hash in self.get_block_transaction_hashes(header_to_remove):
                    self._remove_transaction_from_canonical_chain(transaction_hash)
                for transaction_hash in self.get_block_receive_transaction_hashes(header_to_remove):
                    self._remove_transaction_from_canonical_chain(transaction_hash)

            del(self.db[SchemaV1.make_canonical_head_hash_lookup_key(wallet_address)])


    # TODO: update this to take a `hash` rather than a full header object.
    #this also accepts a header that has a smaller block number than the current header
    #in which case it will trunkate the chain.
    def _set_as_canonical_chain_head(self, header: BlockHeader, wallet_address = None) -> Tuple[BlockHeader, ...]:
        """
        Returns iterable of headers newly on the canonical head
        """
        try:
            self.get_block_header_by_hash(header.hash)
        except HeaderNotFound:
            raise ValueError("Cannot use unknown block hash as canonical head: {}".format(
                header.hash))

        if wallet_address is None:
            wallet_address = self.wallet_address

        try:
            canonical_header = self.get_canonical_head(wallet_address = wallet_address)
        except CanonicalHeadNotFound:
            canonical_header = None

        if canonical_header is not None and header.block_number <= canonical_header.block_number:
            for i in range(header.block_number +1, canonical_header.block_number+1):
                header_to_remove = self.get_canonical_block_header_by_number(i, wallet_address = wallet_address)
                for transaction_hash in self.get_block_transaction_hashes(header_to_remove):
                    self._remove_transaction_from_canonical_chain(transaction_hash)
                for transaction_hash in self.get_block_receive_transaction_hashes(header_to_remove):
                    self._remove_transaction_from_canonical_chain(transaction_hash)

            new_canonical_headers = tuple()

        else:
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
                    for transaction_hash in self.get_block_receive_transaction_hashes(old_header):
                        self._remove_transaction_from_canonical_chain(transaction_hash)

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

    def get_number_of_send_tx_in_block(self, block_hash):
        '''
        returns the number of send tx in a block
        '''
        #get header
        header = self.get_block_header_by_hash(block_hash)

        return self._get_block_transaction_count(header.transaction_root)

    @classmethod
    def get_chain_wallet_address_for_block_hash(cls, db, block_hash):
        block_hash_save_key = SchemaV1.make_block_hash_to_chain_wallet_address_lookup_key(block_hash)
        try:
            return db[block_hash_save_key]
        except KeyError:
            raise ValueError("Block hash {} not found in database".format(block_hash))

    def get_chain_wallet_address_for_block(self, block):
        if block.header.block_number == 0:
            return block.header.sender
        else:
            return self.get_chain_wallet_address_for_block_hash(self.db, block.header.parent_hash)


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

        if block.reward_bundle is not None:
            self.persist_reward_bundle(block.reward_bundle)
            self.set_latest_reward_block_number(block.sender, block.number)

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

    def persist_non_canonical_block(self, block, wallet_address):
        self.save_header_to_db(block.header)

        if block.reward_bundle is not None:
            self.persist_reward_bundle(block.reward_bundle)

        self.save_block_hash_to_chain_wallet_address(block.hash, wallet_address)

        #add all receive transactions as children to the sender block
        self.add_block_receive_transactions_to_parent_child_lookup(block.header, block.receive_transaction_class)

        #we also have to save this block as the child of the parent block in the same chain
        if block.header.parent_hash != GENESIS_PARENT_HASH:
            self.add_block_child(block.header.parent_hash, block.header.hash)

    #
    # Unprocessed Block API
    #
    def save_block_as_unprocessed(self, block, wallet_address):
        '''
        This saves the block as unprocessed, and saves to any unprocessed parents, including the one on this own chain and from receive transactions
        '''
        self.logger.debug("saving block number {} as unprocessed on chain {}. the block hash is {}".format(block.number, encode_hex(wallet_address), encode_hex(block.hash)))
        self.save_unprocessed_block_lookup(block.hash, block.number, wallet_address)
        if self.is_block_unprocessed(block.header.parent_hash):
            self.save_unprocessed_children_block_lookup(block.header.parent_hash)

        self.save_unprocessed_children_block_lookup_to_transaction_parents(block)
        self.save_unprocessed_children_block_lookup_to_reward_proof_parents(block)

    def remove_block_from_unprocessed(self, block):
        '''
        This removes any unprocessed lookups for this block.
        '''
        if self.is_block_unprocessed(block.hash):
            #delete the two unprocessed lookups for this block
            self.delete_unprocessed_block_lookup(block.hash, block.number)

            #delete all unprocessed lookups for transaction parents if nessisary
            self.delete_unprocessed_children_block_lookup_to_transaction_parents_if_nessissary(block)

            #delete all unprocessed lookups for chain parent if nessisary
            if not self.check_all_children_blocks_to_see_if_any_unprocessed(block.header.parent_hash):
                self.delete_unprocessed_children_blocks_lookup(block.header.parent_hash)



    def save_unprocessed_block_lookup(self, block_hash, block_number, wallet_address):
        lookup_key = SchemaV1.make_unprocessed_block_lookup_key(block_hash)
        self.db[lookup_key] = b'1'


        lookup_key = SchemaV1.make_unprocessed_block_lookup_by_number_key(wallet_address, block_number)
        self.db[lookup_key] = rlp.encode(block_hash, sedes=rlp.sedes.binary)


    def save_unprocessed_children_block_lookup(self, block_hash):
        lookup_key = SchemaV1.make_has_unprocessed_block_children_lookup_key(block_hash)
        self.db[lookup_key] = b'1'

        #need to also save for all receive transaction parents

    def save_unprocessed_children_block_lookup_to_transaction_parents(self, block):

        for receive_transaction in block.receive_transactions:
            #or do we not even have the block
            if self.is_block_unprocessed(receive_transaction.sender_block_hash) or not self.db.exists(receive_transaction.sender_block_hash):
                self.logger.debug("saving parent children unprocessed block lookup for block hash {}".format(encode_hex(receive_transaction.sender_block_hash)))
                self.save_unprocessed_children_block_lookup(receive_transaction.sender_block_hash)

    def save_unprocessed_children_block_lookup_to_reward_proof_parents(self, block: 'BaseBlock') -> None:
        if block.reward_bundle is not None:
            if block.reward_bundle.reward_type_2.amount != 0:
                for node_staking_score in block.reward_bundle.reward_type_2.proof:
                    if self.is_block_unprocessed(node_staking_score.head_hash_of_sender_chain) or not self.db.exists(node_staking_score.head_hash_of_sender_chain):
                        self.logger.debug("saving parent children unprocessed block lookup for block hash {}".format(encode_hex(node_staking_score.head_hash_of_sender_chain)))
                        self.save_unprocessed_children_block_lookup(node_staking_score.head_hash_of_sender_chain)

    def delete_unprocessed_children_block_lookup_to_transaction_parents_if_nessissary(self, block):

        for receive_transaction in block.receive_transactions:
            #or do we not even have the block
            if not self.check_all_children_blocks_to_see_if_any_unprocessed(receive_transaction.sender_block_hash) :
                self.delete_unprocessed_children_blocks_lookup(receive_transaction.sender_block_hash)



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

    def is_block_unprocessed(self, block_hash: Hash32) -> bool:
        '''
        Returns True if the block is unprocessed
        '''
        #if block_hash == GENESIS_PARENT_HASH:
        #    return True
        lookup_key = SchemaV1.make_unprocessed_block_lookup_key(block_hash)
        try:
            self.db[lookup_key]
            return True
        except KeyError:
            return False

    def get_unprocessed_block_hash_by_block_number(self, wallet_address, block_number):
        '''
        Returns block hash if the block is unprocessed, false if it doesnt exist for this block number
        '''

        lookup_key = SchemaV1.make_unprocessed_block_lookup_by_number_key(wallet_address, block_number)
        try:
            return rlp.decode(self.db[lookup_key], sedes = rlp.sedes.binary)
        except KeyError:
            return None



    def delete_unprocessed_block_lookup(self, block_hash, block_number):
        lookup_key = SchemaV1.make_unprocessed_block_lookup_key(block_hash)
        try:
            del(self.db[lookup_key])
        except KeyError:
            pass

        wallet_address = self.get_chain_wallet_address_for_block_hash(self.db, block_hash)

        lookup_key = SchemaV1.make_unprocessed_block_lookup_by_number_key(wallet_address, block_number)

        try:
            del(self.db[lookup_key])
        except KeyError:
            pass


    def delete_unprocessed_children_blocks_lookup(self, block_hash):
        '''
        removes the lookup that says if this block has unprocessed children
        '''
        lookup_key = SchemaV1.make_has_unprocessed_block_children_lookup_key(block_hash)
        try:
            del(self.db[lookup_key])
        except KeyError:
            pass


    def check_all_children_blocks_to_see_if_any_unprocessed(self, block_hash):
        '''
        manually goes through all children blocks instead of using lookup table. 
        if any children are unprocessed, it returns true, false otherwise.
        '''
        if not self.has_unprocessed_children(block_hash):
            return False

        children_block_hashes = self.get_block_children(block_hash)
        if children_block_hashes == None:
            return False

        for child_block_hash in children_block_hashes:
            if self.is_block_unprocessed(child_block_hash):
                return True

        return False




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

    def _get_block_transaction_count(self, transaction_root: Hash32):
        '''
        Returns iterable of the encoded transactions for the given block header
        '''
        count = 0
        transaction_db = HexaryTrie(self.db, root_hash=transaction_root)
        for transaction_idx in itertools.count():
            transaction_key = rlp.encode(transaction_idx)
            if transaction_key not in transaction_db:
                return count
            count += 1

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

    def remove_block_receive_transactions_to_parent_child_lookup(self, block_header, transaction_class):
        block_receive_transactions = self.get_block_receive_transactions(block_header,
                                                                        transaction_class)

        for receive_transaction in block_receive_transactions:
            self.remove_block_child(
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

    def remove_block_from_all_parent_child_lookups(self, block_header, transaction_class):
        '''
        Removes block from parent child lookups coming from transactions, and from within the chain.
        '''
        self.remove_block_receive_transactions_to_parent_child_lookup(block_header, transaction_class)
        self.remove_block_child(block_header.parent_hash, block_header.hash)



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

    def get_all_descendant_block_hashes(self, block_hash: Hash32):
        validate_word(block_hash, title="Block_hash")
        descentant_blocks = self._get_all_descendant_block_hashes(block_hash)
        return descentant_blocks

    def _get_all_descendant_block_hashes(self, block_hash: Hash32):

        #lookup children
        children = self.get_block_children(block_hash)

        if children == None:
            return None
        else:
            child_blocks = set()
            for child_block_hash in children:

                child_blocks.add(child_block_hash)

                sub_children_blocks = self._get_all_descendant_block_hashes(child_block_hash)

                if sub_children_blocks is not None:
                    child_blocks.update(sub_children_blocks)
            return child_blocks

    def save_block_children(self, parent_block_hash: Hash32,
                            block_children):

        validate_word(parent_block_hash, title="Block_hash")
        block_children_lookup_key = SchemaV1.make_block_children_lookup_key(parent_block_hash)
        self.db[block_children_lookup_key] = rlp.encode(block_children, sedes=rlp.sedes.CountableList(hash32))

    def delete_all_block_children(self, parent_block_hash: Hash32):

        validate_word(parent_block_hash, title="Block_hash")
        block_children_lookup_key = SchemaV1.make_block_children_lookup_key(parent_block_hash)
        try:
            del(self.db[block_children_lookup_key])
        except KeyError:
            pass

    #we don't want to count the stake from the origin wallet address. This could allow 51% attacks.The origin chain shouldn't count becuase it is the chain with the conflict.
    def get_block_children_chains(self, block_hash, exclude_chains:List = None) -> List[Address]:
        validate_word(block_hash, title="Block_hash")
        origin_wallet_address = self.get_chain_wallet_address_for_block_hash(self.db, block_hash)
        child_chains = self._get_block_children_chains(block_hash)
        if child_chains is None:
            return None
        try:
            child_chains.remove(origin_wallet_address)
        except KeyError:
            pass
        except AttributeError:
            pass
        if exclude_chains is not None:
            for wallet_address in exclude_chains:
                try:
                    child_chains.remove(wallet_address)
                except KeyError:
                    pass
                except AttributeError:
                    pass
        return list(child_chains)

    def _get_block_children_chains(self, block_hash):
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

    def get_block_number_of_latest_reward_block(self, wallet_address: Address = None) -> BlockNumber:
        if wallet_address is None:
            wallet_address = self.wallet_address
        validate_canonical_address(wallet_address, title="Wallet Address")

        canonical_head = self.get_canonical_head(wallet_address)
        canonical_block_number = canonical_head.block_number

        if canonical_head.reward != b'':
            return canonical_block_number

        if canonical_block_number == 0:
            return BlockNumber(0)

        for i in range(canonical_block_number, -1, -1):
            header = self.get_canonical_block_header_by_number(BlockNumber(i), wallet_address)
            if header.reward != b'':
                return BlockNumber(i)


    #
    # Historical minimum allowed gas price API for throttling the network
    #
    def save_historical_minimum_gas_price(self, historical_minimum_gas_price: List[List[Union[Timestamp, int]]]) -> None:
        '''
        This takes list of timestamp, gas_price. The timestamps are every minute
        '''
        lookup_key = SchemaV1.make_historical_minimum_gas_price_lookup_key()
        encoded_data = rlp.encode(historical_minimum_gas_price[-MAX_NUM_HISTORICAL_MIN_GAS_PRICE_TO_KEEP:],sedes=CountableList(rlp.sedes.List([big_endian_int, big_endian_int])))
        self.db.set(
            lookup_key,
            encoded_data,
        )


    def load_historical_minimum_gas_price(self, mutable:bool = True, sort:bool = False) -> Optional[List[List[Union[Timestamp, int]]]]:
        '''
        saved as timestamp, min gas price
        '''
        lookup_key = SchemaV1.make_historical_minimum_gas_price_lookup_key()
        try:
            data = rlp.decode(self.db[lookup_key], sedes=CountableList(rlp.sedes.List([big_endian_int, big_endian_int])))
            if sort:
                if len(data) > 0:
                    sorted_data = SortedList(data)
                    data = tuple(sorted_data)

            if mutable:
                return make_mutable(data)
            else:
                return data
        except KeyError:
            return None


    def save_historical_tx_per_centisecond(self, historical_tx_per_centisecond, de_sparse = True):
        '''
        This takes list of timestamp, tx_per_minute. The timestamps are every minute, tx_per_minute must be an intiger
        this one is naturally a sparse list because some 100 second intervals might have no tx. So we can de_sparse it.
        '''
        if de_sparse:
            historical_tx_per_centisecond = de_sparse_timestamp_item_list(historical_tx_per_centisecond, 100, filler = 0)
        lookup_key = SchemaV1.make_historical_tx_per_centisecond_lookup_key()
        encoded_data = rlp.encode(historical_tx_per_centisecond[-MAX_NUM_HISTORICAL_MIN_GAS_PRICE_TO_KEEP:],sedes=CountableList(rlp.sedes.List([big_endian_int, big_endian_int])))
        self.db.set(
            lookup_key,
            encoded_data,
        )

    def load_historical_tx_per_centisecond(self, mutable = True, sort = False):
        '''
        returns a list of [timestamp, tx/centisecond]
        '''

        lookup_key = SchemaV1.make_historical_tx_per_centisecond_lookup_key()
        try:
            data = rlp.decode(self.db[lookup_key], sedes=CountableList(rlp.sedes.List([big_endian_int, big_endian_int])))
            if sort:
                if len(data) > 0:
                    sorted_data = SortedList(data)
                    data = tuple(sorted_data)

            if mutable:
                return make_mutable(data)
            else:
                return data
        except KeyError:
            return None

    def save_historical_network_tpc_capability(self, historical_tpc_capability: List[List[Union[Timestamp, int]]], de_sparse: bool = False) -> None:
        '''
        This takes list of timestamp, historical_tpc_capability. The timestamps are every minute, historical_tpc_capability must be an intiger
        '''
        if de_sparse:
            historical_tpc_capability = de_sparse_timestamp_item_list(historical_tpc_capability, 100, filler = None)
        lookup_key = SchemaV1.make_historical_network_tpc_capability_lookup_key()
        encoded_data = rlp.encode(historical_tpc_capability[-MAX_NUM_HISTORICAL_MIN_GAS_PRICE_TO_KEEP:],sedes=CountableList(rlp.sedes.List([big_endian_int, big_endian_int])))
        self.db.set(
            lookup_key,
            encoded_data,
        )

    def save_current_historical_network_tpc_capability(self, current_tpc_capability):
        validate_uint256(current_tpc_capability, title="current_tpc_capability")
        existing = self.load_historical_network_tpc_capability()
        current_centisecond = int(time.time()/100) * 100
        existing.append([current_centisecond, current_tpc_capability])
        self.save_historical_network_tpc_capability(existing, de_sparse = True)


#    def update_historical_network_tpc_capability(self, timestamp, network_tpc_cap, perform_validation = True):
#        if perform_validation:
#            validate_centisecond_timestamp(timestamp, title="timestamp")
#            validate_uint256(network_tpc_cap, title="network_tpc_cap")




    def load_historical_network_tpc_capability(self, mutable:bool = True, sort:bool = False) -> Optional[List[List[Union[Timestamp, int]]]]:
        '''
        Returns a list of [timestamp, transactions per second]
        :param mutable:
        :param sort:
        :return:
        '''
        lookup_key = SchemaV1.make_historical_network_tpc_capability_lookup_key()
        try:
            data = rlp.decode(self.db[lookup_key], sedes=CountableList(rlp.sedes.List([big_endian_int, big_endian_int])))
            if sort:
                if len(data) > 0:
                    sorted_data = SortedList(data)
                    data = tuple(sorted_data)

            if mutable:
                return make_mutable(data)
            else:
                return data
        except KeyError:
            return None


    def calculate_next_centisecond_minimum_gas_price(self, historical_minimum_allowed_gas, historical_tx_per_centisecond, goal_tx_per_centisecond):
        average_centisecond_delay = MIN_GAS_PRICE_CALCULATION_AVERAGE_DELAY
        average_centisecond_window_length = MIN_GAS_PRICE_CALCULATION_AVERAGE_WINDOW_LENGTH
        min_centisecond_time_between_change_in_minimum_gas = MIN_GAS_PRICE_CALCULATION_MIN_TIME_BETWEEN_CHANGE_IN_MIN_GAS_PRICE

        if not len(historical_minimum_allowed_gas) >= min_centisecond_time_between_change_in_minimum_gas:
            raise NotEnoughDataForHistoricalMinGasPriceCalculation('historical_minimum_allowed_gas too short. it is a lenght of {}, but should be a length of {}'.format(len(historical_minimum_allowed_gas),min_centisecond_time_between_change_in_minimum_gas))
        if not len(historical_tx_per_centisecond) > average_centisecond_delay+average_centisecond_window_length:
            raise NotEnoughDataForHistoricalMinGasPriceCalculation('historical_tx_per_centisecond too short. it is a length of {}, but should be a length of {}'.format(len(historical_tx_per_centisecond),average_centisecond_delay+average_centisecond_window_length))


        if not are_items_in_list_equal(historical_minimum_allowed_gas[-1*min_centisecond_time_between_change_in_minimum_gas:]):
            #we have to wait longer to change minimum gas
            return historical_minimum_allowed_gas[-1]
        else:
            my_sum = sum(historical_tx_per_centisecond[-average_centisecond_delay-average_centisecond_window_length:-average_centisecond_delay])
            average = my_sum/average_centisecond_window_length

            error = average - goal_tx_per_centisecond


            if error > 1:
                new_minimum_allowed_gas = historical_minimum_allowed_gas[-1] + 1
            elif error < -1:
                new_minimum_allowed_gas = historical_minimum_allowed_gas[-1] -1
            else:
                new_minimum_allowed_gas = historical_minimum_allowed_gas[-1]

            if new_minimum_allowed_gas < 1:
                new_minimum_allowed_gas = 1

            return new_minimum_allowed_gas

    def initialize_historical_minimum_gas_price_at_genesis(self, min_gas_price, net_tpc_cap, tpc = None):
        current_centisecond = int(time.time()/100) * 100

        historical_minimum_gas_price = []
        historical_tx_per_centisecond = []
        historical_tpc_capability = []

        for timestamp in range(current_centisecond-100*50, current_centisecond+100, 100):
            historical_minimum_gas_price.append([timestamp, min_gas_price])
            if tpc is not None:
                historical_tx_per_centisecond.append([timestamp, tpc])
            else:
                if min_gas_price <= 1:
                    historical_tx_per_centisecond.append([timestamp, 0])
                else:
                    historical_tx_per_centisecond.append([timestamp, int(net_tpc_cap*0.94)])
            historical_tpc_capability.append([timestamp, net_tpc_cap])

        self.save_historical_minimum_gas_price(historical_minimum_gas_price)
        self.save_historical_tx_per_centisecond(historical_tx_per_centisecond, de_sparse = False)
        self.save_historical_network_tpc_capability(historical_tpc_capability, de_sparse = False)




    def recalculate_historical_mimimum_gas_price(self, start_timestamp, end_timestamp = None):
        #we just have to delete the ones in front of this time and update
        self.delete_newer_historical_mimimum_gas_price(start_timestamp)

        #then update the missing items:
        self.update_historical_mimimum_gas_price(end_timestamp=end_timestamp)

    def delete_newer_historical_mimimum_gas_price(self, start_timestamp):
        self.logger.debug("deleting historical min gas price newer than {}".format(start_timestamp))
        hist_min_gas_price = self.load_historical_minimum_gas_price()

        if (hist_min_gas_price is None
            or len(hist_min_gas_price) < MIN_GAS_PRICE_CALCULATION_MIN_TIME_BETWEEN_CHANGE_IN_MIN_GAS_PRICE):
            #there is no data for calculating min gas price
            raise HistoricalMinGasPriceError("tried to update historical minimum gas price but historical minimum gas price has not been initialized")

        sorted_hist_min_gas_price = SortedDict(hist_min_gas_price)
#        if sorted_hist_min_gas_price.peekitem(0)[0] > start_timestamp:
#            raise HistoricalMinGasPriceError("tried to recalculate historical minimum gas price at timestamp {}, however that timestamp doesnt exist".format(start_timestamp))
#

        #make sure we leave at least the minimum amount to calculate future min gas prices. otherwise we cant do anything.
        if MIN_GAS_PRICE_CALCULATION_MIN_TIME_BETWEEN_CHANGE_IN_MIN_GAS_PRICE > (MIN_GAS_PRICE_CALCULATION_AVERAGE_DELAY + MIN_GAS_PRICE_CALCULATION_AVERAGE_WINDOW_LENGTH):
            min_required_centiseconds_remaining = MIN_GAS_PRICE_CALCULATION_MIN_TIME_BETWEEN_CHANGE_IN_MIN_GAS_PRICE + 3
        else:
            min_required_centiseconds_remaining = (MIN_GAS_PRICE_CALCULATION_AVERAGE_DELAY + MIN_GAS_PRICE_CALCULATION_AVERAGE_WINDOW_LENGTH) + 3

        #we assume we have hist_net_tpc_capability back to at least as early as the earliest hist_min_gas_price, which should always be the case
        earliest_allowed_timestamp = sorted_hist_min_gas_price.keys()[min_required_centiseconds_remaining]
        if start_timestamp < earliest_allowed_timestamp:
            start_timestamp = earliest_allowed_timestamp

        if sorted_hist_min_gas_price.peekitem(-1)[0] > start_timestamp:
            end_timestamp = sorted_hist_min_gas_price.peekitem(-1)[0]+100

            for timestamp in range(start_timestamp, end_timestamp):
                try:
                    del(sorted_hist_min_gas_price[timestamp])
                except KeyError:
                    pass

            hist_min_gas_price = list(sorted_hist_min_gas_price.items())
            #save it with the deleted items
            self.save_historical_minimum_gas_price(hist_min_gas_price)


    def update_historical_mimimum_gas_price(self,end_timestamp=None):
        '''
        needs to be called any time the chains are modified, and any time we lookup required gas price
        it saves the historical block price up to MIN_GAS_PRICE_CALCULATION_AVERAGE_DELAY minutes ago using all information in our database
        '''

        hist_min_gas_price = self.load_historical_minimum_gas_price()

        if (hist_min_gas_price is None
            or len(hist_min_gas_price) < MIN_GAS_PRICE_CALCULATION_MIN_TIME_BETWEEN_CHANGE_IN_MIN_GAS_PRICE):
            #there is no data for calculating min gas price
            raise NotEnoughDataForHistoricalMinGasPriceCalculation("tried to update historical minimum gas price but historical minimum gas price has not been initialized")

        sorted_hist_min_gas_price = SortedList(hist_min_gas_price)

        current_centisecond = int(time.time()/100) * 100

        if sorted_hist_min_gas_price[-1][0] != current_centisecond:

            hist_tx_per_centi = self.load_historical_tx_per_centisecond()
            if hist_tx_per_centi is None:
                #there is no data for calculating min gas price
                raise NotEnoughDataForHistoricalMinGasPriceCalculation("tried to update historical minimum gas price but historical transactions per centisecond is empty")

            if len(hist_tx_per_centi) < (MIN_GAS_PRICE_CALCULATION_AVERAGE_DELAY + MIN_GAS_PRICE_CALCULATION_AVERAGE_WINDOW_LENGTH + 1):
                raise NotEnoughDataForHistoricalMinGasPriceCalculation("tried to update historical minimum gas price but there are not enough entries of historical tx per centisecond")

            sorted_hist_tx_per_centi = SortedList(hist_tx_per_centi)

            #only update if there is a newer entry in hist tx per centi
            if sorted_hist_tx_per_centi[-1][0] <= sorted_hist_min_gas_price[-1][0]:
                self.logger.debug("No need to update historical minimum gas price because there have been no newer transactions")
                return

            hist_network_tpc_cap = self.load_historical_network_tpc_capability()
            if hist_network_tpc_cap is None:
                #there is no data for calculating min gas price
                raise NotEnoughDataForHistoricalMinGasPriceCalculation("tried to update historical minimum gas price but historical network tpc capability is empty")


            hist_network_tpc_cap = dict(hist_network_tpc_cap)

            #now lets do the updating:

            start_timestamp = sorted_hist_min_gas_price[-1][0]+100

            if not end_timestamp:
                end_timestamp = current_centisecond+100
            else:
                if end_timestamp > current_centisecond:
                    end_timestamp = current_centisecond+100
                else:
                    end_timestamp = int(end_timestamp/100) * 100+100

            historical_minimum_allowed_gas = [i[1] for i in sorted_hist_min_gas_price]


            for timestamp in range(start_timestamp, end_timestamp, 100):
                historical_tx_per_centisecond = [i[1] for i in sorted_hist_tx_per_centi if i[0] < timestamp]
                try:
                    goal_tx_per_centisecond = hist_network_tpc_cap[timestamp]
                except KeyError:
                    #lets allow it if it is just the very last one because it may be slightly delaid in updating
                    if timestamp == end_timestamp-100:
                        goal_tx_per_centisecond = hist_network_tpc_cap[end_timestamp-200]
                    else:
                        raise HistoricalNetworkTPCMissing
                next_centisecond_min_gas_price = self.calculate_next_centisecond_minimum_gas_price(historical_minimum_allowed_gas,
                                                                                                   historical_tx_per_centisecond,
                                                                                                   goal_tx_per_centisecond)

                #first make sure we append it to historical_minimum_allowed_gas
                historical_minimum_allowed_gas.append(next_centisecond_min_gas_price)
                #now add it to the sortedList
                sorted_hist_min_gas_price.add([timestamp, next_centisecond_min_gas_price])


            #now lets change it into a list
            hist_min_gas_price = list(sorted_hist_min_gas_price)

            #now remove any that are to old.
            if len(hist_min_gas_price) > MAX_NUM_HISTORICAL_MIN_GAS_PRICE_TO_KEEP:
                hist_min_gas_price = hist_min_gas_price[-MAX_NUM_HISTORICAL_MIN_GAS_PRICE_TO_KEEP:]

            #and finally save it
            self.save_historical_minimum_gas_price(hist_min_gas_price)



    def get_required_block_min_gas_price(self, block_timestamp):
        '''
        it is important that this doesn't run until our blockchain is up to date. If it is run before that,
        it will give the wrong number.
        '''
        centisecond_window = int(block_timestamp/100) * 100


        hist_min_gas_price = self.load_historical_minimum_gas_price()

        if hist_min_gas_price is None:
            #there is no data for calculating min gas price
            raise HistoricalMinGasPriceError("tried to get required block minimum gas price but historical minimum gas price has not been initialized")

        dict_hist_min_gas_price = dict(hist_min_gas_price)

        #self.logger.debug('get_required_block_min_gas_price, centisecond_window = {}, dict_hist_min_gas_price = {}'.format(centisecond_window, dict_hist_min_gas_price))
        try:
            return dict_hist_min_gas_price[centisecond_window]
        except KeyError:
            pass

        #if we don't have this centisecond_window, lets return the previous one.
        try:
            return dict_hist_min_gas_price[centisecond_window-100]
        except KeyError:
            pass


        raise HistoricalMinGasPriceError("Could not get required block min gas price for block timestamp {}".format(block_timestamp))

    def min_gas_system_initialization_required(self):
        test_1 = self.load_historical_minimum_gas_price(mutable = False)
        test_3 = self.load_historical_network_tpc_capability(mutable = False)

        if test_1 is None or test_3 is None:
            return True

        min_centisecond_window = int(time.time()/100) * 100-100*15
        sorted_test_3 = SortedList(test_3)
        if sorted_test_3[-1][0] < min_centisecond_window:
            return True

        return False

    #
    # Reward bundle persisting
    #

    def persist_reward_bundle(self, reward_bundle: StakeRewardBundle) -> None:
        lookup_key = SchemaV1.make_reward_bundle_hash_lookup_key(reward_bundle.hash)
        self.db[lookup_key] = rlp.encode(reward_bundle, sedes=StakeRewardBundle)

    def get_reward_bundle(self, reward_bundle_hash: Hash32) -> StakeRewardBundle:
        validate_is_bytes(reward_bundle_hash, 'reward_bundle_hash')
        lookup_key = SchemaV1.make_reward_bundle_hash_lookup_key(reward_bundle_hash)
        try:
            encoded = self.db[lookup_key]
            return rlp.decode(encoded, sedes=StakeRewardBundle)
        except KeyError:
            return None

    def get_latest_reward_block_number(self, wallet_address: Address) -> BlockNumber:
        validate_canonical_address(wallet_address, title="wallet_address")

        key = SchemaV1.make_latest_reward_block_number_lookup(wallet_address)
        rlp_latest_block_number = self.db.get(key, b'')
        if rlp_latest_block_number:
            # in order to save some headache elsewhere, if a block is deleted for any reason, we won't reset this number
            # so lets also check to make sure the block with this number has a reward
            block_number = rlp.decode(rlp_latest_block_number, sedes=rlp.sedes.f_big_endian_int)
            try:
                block_header = self.get_canonical_block_header_by_number(block_number)
            except HeaderNotFound:
                # need to find previous reward block and save new one
                latest_reward_block_number = self.get_block_number_of_latest_reward_block(wallet_address)
                self.set_latest_reward_block_number(wallet_address, latest_reward_block_number)
                return latest_reward_block_number

            if block_header.reward_hash == ZERO_HASH32:
                # need to find previous reward block and save new one
                latest_reward_block_number = self.get_block_number_of_latest_reward_block(wallet_address)
                self.set_latest_reward_block_number(wallet_address, latest_reward_block_number)
                return latest_reward_block_number

            return block_number
        else:
            return BlockNumber(0)

    def set_latest_reward_block_number(self, wallet_address: Address, block_number: BlockNumber) -> None:
        validate_canonical_address(wallet_address, title="wallet_address")

        key = SchemaV1.make_latest_reward_block_number_lookup(wallet_address)

        self.db[key] = rlp.encode(block_number, sedes=rlp.sedes.f_big_endian_int)


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

# TODO: remove this commented class
# this class has been moved to helios
# class AsyncChainDB(ChainDB):
#
#     async def coro_get_block_header_by_hash(self, block_hash: Hash32) -> BlockHeader:
#         raise NotImplementedError()
#
#     async def coro_get_canonical_head(self) -> BlockHeader:
#         raise NotImplementedError()
#
#     async def coro_header_exists(self, block_hash: Hash32) -> bool:
#         raise NotImplementedError()
#
#     async def coro_get_canonical_block_hash(self, block_number: BlockNumber) -> Hash32:
#         raise NotImplementedError()
#
#     async def coro_persist_header(self, header: BlockHeader) -> Tuple[BlockHeader, ...]:
#         raise NotImplementedError()
#
#     async def coro_persist_trie_data_dict(self, trie_data_dict: Dict[bytes, bytes]) -> None:
#         raise NotImplementedError()
