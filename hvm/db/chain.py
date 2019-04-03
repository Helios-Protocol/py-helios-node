import bisect
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
    Set,
    Tuple,
    Type,
    TYPE_CHECKING,
    Union,
    Optional,
)

from hvm.types import Timestamp

import rlp_cython as rlp

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
    BLANK_REWARD_HASH)
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

from hvm.rlp.consensus import StakeRewardBundle, BaseRewardBundle
from hvm.rlp import sedes as evm_rlp_sedes
from hvm.rlp.sedes import(
    trie_root,
    address,
    hash32,

)
from rlp_cython.sedes import(
    big_endian_int,
    CountableList,
    binary,
)


from hvm.db.journal import (
    JournalDB,
)

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
    def remove_block_from_canonical_block_hash_lookup(self, block_number: BlockNumber, chain_address: Address) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_canonical_block_header_by_number(self, block_number: BlockNumber, wallet_address: Address) -> BlockHeader:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_canonical_block_hash(self, block_number: BlockNumber, chain_address: Address) -> Hash32:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_canonical_head(self, wallet_address: Address) -> BlockHeader:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_canonical_head_hash(self, wallet_address: Address) -> Hash32:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_all_block_hashes_on_chain(self, chain_address: Address) -> List[Hash32]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_all_block_hashes_on_chain_by_head_block_hash(self, chain_head_hash: Hash32) -> List[Hash32]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def delete_canonical_chain(self, chain_address: Address) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def is_in_canonical_chain(self, block_hash: Hash32) -> bool:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def delete_block_from_canonical_chain(self, block_hash: Hash32) -> None:
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
    def persist_non_canonical_block(self, block: 'BaseBlock'):
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def save_block_as_unprocessed(self, block: 'BaseBlock') -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def remove_block_from_unprocessed(self, block: 'BaseBlock') -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def save_unprocessed_block_lookup(self, block_hash: Hash32, block_number: BlockNumber, chain_address: Address) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def save_unprocessed_children_block_lookup(self, block_hash: Hash32) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def save_unprocessed_children_block_lookup_to_transaction_parents(self, block: 'BaseBlock') -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def save_unprocessed_children_block_lookup_to_reward_proof_parents(self, block: 'BaseBlock') -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def delete_unprocessed_children_block_lookup_to_transaction_parents_if_nessissary(self, block: 'BaseBlock') -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def has_unprocessed_children(self, block_hash: Hash32) -> bool:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_chain_wallet_address_for_block_hash(self, block_hash: Hash32) -> Address:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_number_of_send_tx_in_block(self, block_hash):
        raise NotImplementedError("ChainDB classes must implement this method")

    #
    # Transaction API
    #
    @abstractmethod
    def add_receipt(self, block_header: BlockHeader, index_key: int, receipt: Receipt, send_or_receive) -> Hash32:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def add_transaction(self,
                        block_header: BlockHeader,
                        index_key: int, transaction: 'BaseTransaction') -> Hash32:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def add_receive_transaction(self,
                                block_header: BlockHeader,
                                index_key: int,
                                transaction: 'BaseReceiveTransaction') -> Hash32:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_block_transactions(
            self,
            block_header: BlockHeader,
            transaction_class: Type['BaseTransaction']) -> Iterable['BaseTransaction']:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_block_receive_transactions(
            self,
            header: BlockHeader,
            transaction_class: Type['BaseReceiveTransaction']) -> Iterable['BaseReceiveTransaction']:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_block_transaction_hashes(self, block_header: BlockHeader) -> Iterable[Hash32]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_block_receive_transaction_hashes(self, block_header: BlockHeader) -> Iterable[Hash32]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_receipts(self,
                     header: BlockHeader,
                     receipt_class: Type[Receipt]) -> Iterable[Receipt]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_transaction_receipt(self, tx_hash: Hash32) -> Receipt:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_cumulative_gas_used(self, tx_hash: Hash32) -> int:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_receipt_by_idx(self,
                           header: BlockHeader,
                           receipt_idx: int,
                           receipt_class: Type[Receipt] = Receipt) -> Optional[Receipt]:
        raise NotImplementedError("ChainDB classes must implement this method")

    # @abstractmethod
    # def get_transaction_by_index(
    #         self,
    #         block_number: BlockNumber,
    #         transaction_index: int,
    #         transaction_class: Type['BaseTransaction']) -> 'BaseTransaction':
    #     raise NotImplementedError("ChainDB classes must implement this method")

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
    def get_transaction_by_hash(self,
                                tx_hash: Hash32,
                                send_tx_class: Type['BaseTransaction'],
                                receive_tx_class: Type['BaseReceiveTransaction']) -> Union['BaseTransaction', 'BaseReceiveTransaction']:
        raise NotImplementedError("ChainDB classes must implement this method")


    @abstractmethod
    def get_transaction_index(self, transaction_hash: Hash32) -> Tuple[BlockNumber, int, bool]:
        raise NotImplementedError("ChainDB classes must implement this method")

    #
    # Unprocessed block API
    #
    @abstractmethod
    def is_block_unprocessed(self, block_hash: Hash32) -> bool:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_unprocessed_block_hash_by_block_number(self, chain_address: Address, block_number: BlockNumber) -> Optional[Hash32]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def delete_unprocessed_block_lookup(self, block_hash: Hash32, block_number: BlockNumber) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def delete_unprocessed_children_blocks_lookup(self, block_hash: Hash32) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def check_all_children_blocks_to_see_if_any_unprocessed(self, block_hash: Hash32) -> bool:
        raise NotImplementedError("ChainDB classes must implement this method")

    #
    # Block children and Stake API
    #
    @abstractmethod
    def add_block_receive_transactions_to_parent_child_lookup(self, block_header: 'BlockHeader',
                                                              transaction_class: Type[
                                                                  'BaseReceiveTransaction']) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def add_block_rewards_to_parent_child_lookup(self, block_header: 'BlockHeader',
                                                 reward_bundle: BaseRewardBundle) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def remove_block_receive_transactions_to_parent_child_lookup(self, block_header: 'BlockHeader',
                                                                 transaction_class: Type['BaseReceiveTransaction']) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def remove_block_child(self,
                           parent_block_hash: Hash32,
                           child_block_hash: Hash32) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def remove_block_from_all_parent_child_lookups(self, block_header: 'BlockHeader',
                                                   receive_transaction_class: Type['BaseReceiveTransaction']) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def add_block_child(self,
                        parent_block_hash: Hash32,
                        child_block_hash: Hash32) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_block_children(self, parent_block_hash: Hash32) -> List[Hash32]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_all_descendant_block_hashes(self, block_hash: Hash32) -> List[Hash32]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def save_block_children(self, parent_block_hash: Hash32,
                            block_children: List[Hash32]) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def delete_all_block_children_lookups(self, parent_block_hash: Hash32) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_block_children_chains(self, block_hash: Hash32, exclude_chains:Set = None) -> Set[Address]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_block_stake_from_children(self, block_hash: Hash32, exclude_chains: Set = None) -> int:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_total_block_stake_of_block_hashes(self, block_hashes: List[Hash32]) -> int:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_mature_stake(self, wallet_address: Address, timestamp: Timestamp = None,
                         raise_canonical_head_not_found_error: bool = False) -> int:
         raise NotImplementedError("ChainDB classes must implement this method")
    #
    # Historical minimum allowed gas price API for throttling the network
    #
    @abstractmethod
    def save_historical_minimum_gas_price(self,
                                          historical_minimum_gas_price: List[List[Union[Timestamp, int]]]) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def load_historical_minimum_gas_price(self, sort: bool = False) -> Optional[List[List[Union[Timestamp, int]]]]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def save_historical_tx_per_centisecond(self, historical_tx_per_centisecond: List[List[int]], de_sparse=True) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def load_historical_tx_per_centisecond(self, sort=False) -> Optional[List[List[int]]]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def save_historical_network_tpc_capability(self, historical_tpc_capability: List[List[Union[Timestamp, int]]],
                                               de_sparse: bool = False) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def save_current_historical_network_tpc_capability(self, current_tpc_capability: int) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def load_historical_network_tpc_capability(self, sort: bool = False) -> Optional[List[List[Union[Timestamp, int]]]]:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def initialize_historical_minimum_gas_price_at_genesis(self, min_gas_price: int, net_tpc_cap: int,
                                                           tpc: int = None) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_required_block_min_gas_price(self, block_timestamp: Timestamp = None) -> int:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def min_gas_system_initialization_required(self) -> bool:
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

    #
    # Reward bundle processing
    #
    @abstractmethod
    def get_latest_reward_block_number(self, wallet_address: Address) -> BlockNumber:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def set_latest_reward_block_number(self, wallet_address: Address, block_number: BlockNumber) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_block_number_of_latest_reward_block(self, wallet_address: Address) -> BlockNumber:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def persist_reward_bundle(self, reward_bundle: BaseRewardBundle) -> None:
        raise NotImplementedError("ChainDB classes must implement this method")

    @abstractmethod
    def get_reward_bundle(self, reward_bundle_hash: Hash32,
                          reward_bundle_class: Type[BaseRewardBundle]) -> BaseRewardBundle:
        raise NotImplementedError("ChainDB classes must implement this method")

class ChainDB(BaseChainDB):
    logger = logging.getLogger('hvm.db.chain_db.ChainDB')
    _journaldb = None

    def __init__(self, db: BaseDB) -> None:
        self.db = db



    #
    # Canonical Chain API
    #
    def get_canonical_block_hash(self, block_number: BlockNumber, chain_address: Address) -> Hash32:
        """
        Return the block hash for the given block number.
        """

        validate_uint256(block_number, title="Block Number")
        number_to_hash_key = SchemaV1.make_block_number_to_hash_lookup_key(chain_address, block_number)
        try:
            return rlp.decode(
                self.db[number_to_hash_key],
                sedes=rlp.sedes.binary,
            )
        except KeyError:
            self.logger.debug
            raise HeaderNotFound(
                "No header found on the canonical chain {} with number {}".format(chain_address, block_number)
            )

    def remove_block_from_canonical_block_hash_lookup(self, block_number: BlockNumber, chain_address: Address) -> None:
        '''
        Deletes the block number from the get_canonical_block_hash lookup
        :param block_number:
        :param chain_address:
        :return:
        '''

        validate_uint256(block_number, title="Block Number")
        number_to_hash_key = SchemaV1.make_block_number_to_hash_lookup_key(chain_address, block_number)
        try:
            del(self.db[number_to_hash_key])
        except KeyError:
            pass


    def get_canonical_block_header_by_number(self, block_number: BlockNumber, chain_address: Address) -> BlockHeader:
        """
        Returns the block header with the given number in the canonical chain.

        Raises HeaderNotFound if there's no block header with the given number in the
        canonical chain.
        """

        validate_uint256(block_number, title="Block Number")
        return self.get_block_header_by_hash(self.get_canonical_block_hash(block_number, chain_address))

    def get_canonical_head(self, chain_address: Address) -> BlockHeader:
        """
        Returns the current block header at the head of the chain.

        Raises CanonicalHeadNotFound if no canonical head has been set.
        """

        canonical_head_hash = self.get_canonical_head_hash(chain_address)
        return self.get_block_header_by_hash(
            cast(Hash32, canonical_head_hash),
        )

    def get_canonical_head_hash(self, chain_address: Address) -> Hash32:

        try:
            return self.db[SchemaV1.make_canonical_head_hash_lookup_key(chain_address)]
        except KeyError:
            raise CanonicalHeadNotFound("No canonical head set for this chain")

    def get_all_block_hashes_on_chain(self, chain_address: Address) -> List[Hash32]:
        chain_hashes = []

        for block_number in itertools.count():
            try:
                chain_hashes.append(self.get_canonical_block_hash(block_number, chain_address))
            except HeaderNotFound:
                break
        return chain_hashes

    def get_all_block_hashes_on_chain_by_head_block_hash(self, chain_head_hash: Hash32) -> List[Hash32]:
        chain_head_header = self.get_block_header_by_hash(chain_head_hash)
        chain_address = chain_head_header.chain_address
        chain_block_hashes = self.get_all_block_hashes_on_chain(chain_address)
        return chain_block_hashes

    def delete_canonical_chain(self, chain_address: Address) -> None:

        try:
            canonical_header = self.get_canonical_head(chain_address= chain_address)
        except CanonicalHeadNotFound:
            canonical_header = None

        if canonical_header is not None:
            for i in range(0, canonical_header.block_number+1):
                header_to_remove = self.get_canonical_block_header_by_number(i, chain_address= chain_address)
                for transaction_hash in self.get_block_transaction_hashes(header_to_remove):
                    self._remove_transaction_from_canonical_chain(transaction_hash)
                for transaction_hash in self.get_block_receive_transaction_hashes(header_to_remove):
                    self._remove_transaction_from_canonical_chain(transaction_hash)
                self.remove_block_from_canonical_block_hash_lookup(BlockNumber(i), chain_address=chain_address)
            del(self.db[SchemaV1.make_canonical_head_hash_lookup_key(chain_address)])

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

        self._save_header_to_db(header)

        new_headers = self._set_as_canonical_chain_head(header)

        return new_headers



    def _save_header_to_db(self, header: BlockHeader) -> None:
        self.db.set(
            header.hash,
            rlp.encode(header),
        )

    def delete_block_from_canonical_chain(self, block_hash: Hash32) -> None:
        '''
        warning, this will only delete the block and transactions, it will not set the current head number of the chain.
        '''
        try:
            header_to_remove = self.get_block_header_by_hash(block_hash)

            # first check to see if it is in the canonical chain
            canonical_block_hash = self.get_canonical_block_hash(header_to_remove.block_number, header_to_remove.chain_address)

            #if the block doesnt match the canonical block, then it has already been removed from the canonical chain.
            if block_hash == canonical_block_hash:

                for transaction_hash in self.get_block_transaction_hashes(header_to_remove):
                    self._remove_transaction_from_canonical_chain(transaction_hash)
                for transaction_hash in self.get_block_receive_transaction_hashes(header_to_remove):
                    self._remove_transaction_from_canonical_chain(transaction_hash)

                self.remove_block_from_canonical_block_hash_lookup(header_to_remove.block_number, chain_address= header_to_remove.chain_address)

        except HeaderNotFound:
            pass

        #todo: check if you can look up block by number once canonical chain is deleted below




    def is_in_canonical_chain(self, block_hash: Hash32) -> bool:
        try:
            header = self.get_block_header_by_hash(block_hash)
        except HeaderNotFound:
            return False

        block_number = header.block_number
        chain_address = header.chain_address

        try:
            existing_header = self.get_canonical_block_header_by_number(block_number, chain_address)
        except HeaderNotFound:
            return False

        if header.hash == existing_header.hash:
            return True
        else:
            return False



    #this also accepts a header that has a smaller block number than the current header
    #in which case it will trunkate the chain.
    def _set_as_canonical_chain_head(self, header: BlockHeader) -> Tuple[BlockHeader, ...]:
        """
        Returns iterable of headers newly on the canonical head
        """
        try:
            self.get_block_header_by_hash(header.hash)
        except HeaderNotFound:
            raise ValueError("Cannot use unknown block hash as canonical head: {}".format(
                header.hash))

        try:
            canonical_header = self.get_canonical_head(chain_address= header.chain_address)
        except CanonicalHeadNotFound:
            canonical_header = None

        if canonical_header is not None and header.block_number <= canonical_header.block_number:
            for i in range(header.block_number +1, canonical_header.block_number+1):
                header_to_remove = self.get_canonical_block_header_by_number(i, chain_address= header.chain_address)
                for transaction_hash in self.get_block_transaction_hashes(header_to_remove):
                    self._remove_transaction_from_canonical_chain(transaction_hash)
                for transaction_hash in self.get_block_receive_transaction_hashes(header_to_remove):
                    self._remove_transaction_from_canonical_chain(transaction_hash)
                self.remove_block_from_canonical_block_hash_lookup(BlockNumber(i), chain_address= header.chain_address)

            new_canonical_headers = tuple()

        else:
            new_canonical_headers = tuple(reversed(self._find_new_ancestors(header)))

            # remove transaction lookups for blocks that are no longer canonical
            for h in new_canonical_headers:
                try:
                    old_hash = self.get_canonical_block_hash(h.block_number, header.chain_address)
                except HeaderNotFound:
                    # no old block, and no more possible
                    break
                else:
                    old_header = self.get_block_header_by_hash(old_hash)
                    for transaction_hash in self.get_block_transaction_hashes(old_header):
                        self._remove_transaction_from_canonical_chain(transaction_hash)
                        pass
                    for transaction_hash in self.get_block_receive_transaction_hashes(old_header):
                        self._remove_transaction_from_canonical_chain(transaction_hash)

            for h in new_canonical_headers:
                self._add_block_number_to_hash_lookup(h)

        self.db.set(SchemaV1.make_canonical_head_hash_lookup_key(header.chain_address), header.hash)

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
                orig = self.get_canonical_block_header_by_number(h.block_number, h.chain_address)
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
            header.chain_address,
            header.block_number
        )
        self.db.set(
            block_number_to_hash_key,
            rlp.encode(header.hash, sedes=rlp.sedes.binary),
        )


    #
    # Block API
    #
    @functools.lru_cache(maxsize=32)
    def get_number_of_send_tx_in_block(self, block_hash):
        '''
        returns the number of send tx in a block
        '''
        #get header
        header = self.get_block_header_by_hash(block_hash)

        return self._get_block_transaction_count(header.transaction_root)

    def get_chain_wallet_address_for_block_hash(self, block_hash: Hash32) -> Address:
        block_header = self.get_block_header_by_hash(block_hash)
        return block_header.chain_address



    def persist_block(self, block: 'BaseBlock') -> None:
        '''
        Persist the given block's header and uncles.

        Assumes all block transactions have been persisted already.
        '''
        new_canonical_headers = self.persist_header(block.header)

        if not (block.reward_bundle.reward_type_1.amount == 0 and block.reward_bundle.reward_type_2.amount == 0):
            self.persist_reward_bundle(block.reward_bundle)
            self.set_latest_reward_block_number(block.sender, block.number)

        for header in new_canonical_headers:
            for index, transaction_hash in enumerate(self.get_block_transaction_hashes(header)):
                self._add_transaction_to_canonical_chain(transaction_hash, header, index)
            for index, transaction_hash in enumerate(self.get_block_receive_transaction_hashes(header)):
                self._add_receive_transaction_to_canonical_chain(transaction_hash, header, index)

            #add all receive transactions as children to the sender block
            self.add_block_receive_transactions_to_parent_child_lookup(header, block.receive_transaction_class)

        self.add_block_rewards_to_parent_child_lookup(block.header, block.reward_bundle)
        #we also have to save this block as the child of the parent block in the same chain
        if block.header.parent_hash != GENESIS_PARENT_HASH:
            self.add_block_child(block.header.parent_hash, block.header.hash)

    def persist_non_canonical_block(self, block: 'BaseBlock') -> None:
        self._save_header_to_db(block.header)

        if not (block.reward_bundle.reward_type_1.amount == 0 and block.reward_bundle.reward_type_2.amount == 0):
            self.persist_reward_bundle(block.reward_bundle)

        #add all receive transactions as children to the sender block
        self.add_block_receive_transactions_to_parent_child_lookup(block.header, block.receive_transaction_class)

        self.add_block_rewards_to_parent_child_lookup(block.header, block.reward_bundle)

        #we also have to save this block as the child of the parent block in the same chain
        if block.header.parent_hash != GENESIS_PARENT_HASH:
            self.add_block_child(block.header.parent_hash, block.header.hash)

    #
    # Unprocessed Block API
    #
    def save_block_as_unprocessed(self, block: 'BaseBlock') -> None:
        '''
        This saves the block as unprocessed, and saves to any unprocessed parents, including the one on this own chain and from receive transactions
        '''
        self.logger.debug("saving block number {} as unprocessed on chain {}. the block hash is {}".format(block.number, encode_hex(block.header.chain_address), encode_hex(block.hash)))
        self.save_unprocessed_block_lookup(block.hash, block.number, block.header.chain_address)
        if self.is_block_unprocessed(block.header.parent_hash):
            self.save_unprocessed_children_block_lookup(block.header.parent_hash)

        self.save_unprocessed_children_block_lookup_to_transaction_parents(block)
        self.save_unprocessed_children_block_lookup_to_reward_proof_parents(block)

    def remove_block_from_unprocessed(self, block: 'BaseBlock') -> None:
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



    def save_unprocessed_block_lookup(self, block_hash: Hash32, block_number: BlockNumber, chain_address: Address) -> None:
        lookup_key = SchemaV1.make_unprocessed_block_lookup_key(block_hash)
        self.db[lookup_key] = b'1'

        lookup_key = SchemaV1.make_unprocessed_block_lookup_by_number_key(chain_address, block_number)
        self.db[lookup_key] = rlp.encode(block_hash, sedes=rlp.sedes.binary)


    def save_unprocessed_children_block_lookup(self, block_hash: Hash32) -> None:
        lookup_key = SchemaV1.make_has_unprocessed_block_children_lookup_key(block_hash)
        self.db[lookup_key] = b'1'


    def save_unprocessed_children_block_lookup_to_transaction_parents(self, block: 'BaseBlock') -> None:
        for receive_transaction in block.receive_transactions:
            #or do we not even have the block
            if not self.is_in_canonical_chain(receive_transaction.sender_block_hash):
                self.logger.debug("saving parent children unprocessed block lookup for block hash {}".format(encode_hex(receive_transaction.sender_block_hash)))
                self.save_unprocessed_children_block_lookup(receive_transaction.sender_block_hash)

    def save_unprocessed_children_block_lookup_to_reward_proof_parents(self, block: 'BaseBlock') -> None:
        for node_staking_score in block.reward_bundle.reward_type_2.proof:
            if not self.is_in_canonical_chain(node_staking_score.head_hash_of_sender_chain):
                self.logger.debug("saving parent children unprocessed block lookup for reward proof parents block hash {}".format(encode_hex(node_staking_score.head_hash_of_sender_chain)))
                self.save_unprocessed_children_block_lookup(node_staking_score.head_hash_of_sender_chain)

    def delete_unprocessed_children_block_lookup_to_transaction_parents_if_nessissary(self, block: 'BaseBlock') -> None:

        for receive_transaction in block.receive_transactions:
            #or do we not even have the block
            if not self.check_all_children_blocks_to_see_if_any_unprocessed(receive_transaction.sender_block_hash) :
                self.delete_unprocessed_children_blocks_lookup(receive_transaction.sender_block_hash)



    def has_unprocessed_children(self, block_hash: Hash32) -> bool:
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

    def get_unprocessed_block_hash_by_block_number(self, chain_address: Address, block_number: BlockNumber) -> Optional[Hash32]:
        '''
        Returns block hash if the block is unprocessed, false if it doesnt exist for this block number
        '''

        lookup_key = SchemaV1.make_unprocessed_block_lookup_by_number_key(chain_address, block_number)
        try:
            return rlp.decode(self.db[lookup_key], sedes = rlp.sedes.binary)
        except KeyError:
            return None



    def delete_unprocessed_block_lookup(self, block_hash: Hash32, block_number: BlockNumber) -> None:
        lookup_key = SchemaV1.make_unprocessed_block_lookup_key(block_hash)
        try:
            del(self.db[lookup_key])
        except KeyError:
            pass

        wallet_address = self.get_chain_wallet_address_for_block_hash(block_hash)

        lookup_key = SchemaV1.make_unprocessed_block_lookup_by_number_key(wallet_address, block_number)

        try:
            del(self.db[lookup_key])
        except KeyError:
            pass


    def delete_unprocessed_children_blocks_lookup(self, block_hash: Hash32) -> None:
        '''
        removes the lookup that says if this block has unprocessed children
        '''
        lookup_key = SchemaV1.make_has_unprocessed_block_children_lookup_key(block_hash)
        try:
            del(self.db[lookup_key])
        except KeyError:
            pass


    def check_all_children_blocks_to_see_if_any_unprocessed(self, block_hash: Hash32) -> bool:
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
    def add_receipt(self, block_header: BlockHeader, index_key: int, receipt: Receipt, send_or_receive) -> Hash32:
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
            transaction_class: Type['BaseTransaction']) -> Iterable['BaseTransaction']:
        """
        Returns an iterable of transactions for the block speficied by the
        given block header.
        """

        return self._get_block_transactions(header.transaction_root, transaction_class)

    def get_block_receive_transactions(
            self,
            header: BlockHeader,
            transaction_class: Type['BaseReceiveTransaction']) -> Iterable['BaseReceiveTransaction']:
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

    def get_transaction_receipt(self, tx_hash: Hash32) -> Receipt:
        block_hash, index, is_receive = self.get_transaction_index(tx_hash)
        block_header = self.get_block_header_by_hash(block_hash)

        if is_receive:
            num_send_transactions = self.get_number_of_send_tx_in_block(block_hash)
            index += num_send_transactions

        return self.get_receipt_by_idx(block_header, index)

    def get_cumulative_gas_used(self, tx_hash: Hash32) -> int:
        block_hash, index, is_receive = self.get_transaction_index(tx_hash)
        block_header = self.get_block_header_by_hash(block_hash)
        receipts = self.get_receipts(block_header)
        cumulative = 0
        for i in range(index+1):
            cumulative += receipts[i].gas_used
        return cumulative

    def get_receipt_by_idx(self,
                     header: BlockHeader,
                     receipt_idx: int,
                     receipt_class: Type[Receipt] = Receipt) -> Optional[Receipt]:

        receipt_db = HexaryTrie(db=self.db, root_hash=header.receipt_root)

        receipt_key = rlp.encode(receipt_idx)
        try:
            receipt_data = receipt_db[receipt_key]
            return rlp.decode(receipt_data, sedes=receipt_class)
        except KeyError:
            return None

    @to_tuple
    def get_receipts(self,
                     header: BlockHeader,
                     receipt_class: Type[Receipt] = Receipt) -> Iterable[Receipt]:
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

    # def get_transaction_by_index(
    #         self,
    #         block_number: BlockNumber,
    #         transaction_index: int,
    #         transaction_class: Type['BaseTransaction']) -> 'BaseTransaction':
    #     """
    #     Returns the transaction at the specified `transaction_index` from the
    #     block specified by `block_number` from the canonical chain.
    #
    #     Raises TransactionNotFound if no block
    #     """
    #     try:
    #         block_header = self.get_canonical_block_header_by_number(block_number)
    #     except HeaderNotFound:
    #         raise TransactionNotFound("Block {} is not in the canonical chain".format(block_number))
    #     transaction_db = HexaryTrie(self.db, root_hash=block_header.transaction_root)
    #     encoded_index = rlp.encode(transaction_index)
    #     if encoded_index in transaction_db:
    #         encoded_transaction = transaction_db[encoded_index]
    #         return rlp.decode(encoded_transaction, sedes=transaction_class)
    #     else:
    #         raise TransactionNotFound(
    #             "No transaction is at index {} of block {}".format(transaction_index, block_number))

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
                "No transaction is at index {} of block {}".format(transaction_index, block_header))

    def get_receive_transaction_by_index_and_block_hash(
            self,
            block_hash: Hash32,
            transaction_index: int,
            transaction_class: Type['BaseReceiveTransaction']) -> 'BaseReceiveTransaction':
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
                "No transaction is at index {} of block {}".format(transaction_index, block_header))

    def get_transaction_by_hash(self,
                                tx_hash: Hash32,
                                send_tx_class: Type['BaseTransaction'],
                                receive_tx_class: Type['BaseReceiveTransaction']) -> Union['BaseTransaction', 'BaseReceiveTransaction']:

        block_hash, index, is_receive = self.get_transaction_index(tx_hash)
        if is_receive:
            transaction = self.get_receive_transaction_by_index_and_block_hash(
                block_hash,
                index,
                receive_tx_class,
            )
        else:
            transaction = self.get_transaction_by_index_and_block_hash(
                block_hash,
                index,
                send_tx_class,
            )

        return transaction


    # def get_receive_transaction_by_index(
    #         self,
    #         block_number: BlockNumber,
    #         transaction_index: int,
    #         transaction_class: 'BaseReceiveTransaction') -> 'BaseReceiveTransaction':
    #     """
    #     Returns the transaction at the specified `transaction_index` from the
    #     block specified by `block_number` from the canonical chain.
    #
    #     Raises TransactionNotFound if no block
    #     """
    #     try:
    #         block_header = self.get_canonical_block_header_by_number(block_number, chain_address)
    #     except HeaderNotFound:
    #         raise TransactionNotFound("Block {} is not in the canonical chain".format(block_number))
    #     transaction_db = HexaryTrie(self.db, root_hash=block_header.receive_transaction_root)
    #     encoded_index = rlp.encode(transaction_index)
    #     if encoded_index in transaction_db:
    #         encoded_transaction = transaction_db[encoded_index]
    #         return rlp.decode(encoded_transaction, sedes=transaction_class)
    #     else:
    #         raise TransactionNotFound(
    #             "No transaction is at index {} of block {}".format(transaction_index, block_number))

    def get_transaction_index(self, transaction_hash: Hash32) -> Tuple[Hash32, int, bool]:
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
            transaction_class: Union[Type['BaseTransaction'], Type['BaseReceiveTransaction']]) -> Iterable[Union['BaseTransaction', 'BaseReceiveTransaction']]:
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

        transaction_key = TransactionKey(block_header.hash, index, True)
        self.db.set(
            SchemaV1.make_transaction_hash_to_block_lookup_key(transaction_hash),
            rlp.encode(transaction_key),
        )


    #
    # Block children and Stake API
    #
    def add_block_receive_transactions_to_parent_child_lookup(self, block_header: 'BlockHeader', transaction_class: Type['BaseReceiveTransaction']) -> None:
        block_receive_transactions = self.get_block_receive_transactions(block_header,
                                                                        transaction_class)

        for receive_transaction in block_receive_transactions:
            self.add_block_child(
                       receive_transaction.sender_block_hash,
                       block_header.hash)

    def add_block_rewards_to_parent_child_lookup(self, block_header: 'BlockHeader', reward_bundle: BaseRewardBundle) -> None:
        for node_staking_score in reward_bundle.reward_type_2.proof:
            self.logger.debug("saving parent child lookup for reward bundle proof")
            self.add_block_child(node_staking_score.head_hash_of_sender_chain, block_header.hash)


    def remove_block_receive_transactions_to_parent_child_lookup(self, block_header: 'BlockHeader', transaction_class: Type['BaseReceiveTransaction']) -> None:
        block_receive_transactions = self.get_block_receive_transactions(block_header,
                                                                        transaction_class)

        for receive_transaction in block_receive_transactions:
            self.remove_block_child(
                       receive_transaction.sender_block_hash,
                       block_header.hash)


    def remove_block_child(self,
                       parent_block_hash: Hash32,
                       child_block_hash: Hash32) -> None:

        validate_word(parent_block_hash, title="Block_hash")
        validate_word(child_block_hash, title="Block_hash")

        block_children = self.get_block_children(parent_block_hash)

        if block_children is None or child_block_hash not in block_children:
            self.logger.debug("tried to remove a block child that doesnt exist. It was likely already deleted when that block was purged.")
        else:
            block_children.remove(child_block_hash)
            self.save_block_children(parent_block_hash, block_children)

    def remove_block_from_all_parent_child_lookups(self, block_header: 'BlockHeader', receive_transaction_class: Type['BaseReceiveTransaction']) -> None:
        '''
        Removes block from parent child lookups coming from transactions, and from within the chain.
        '''
        self.remove_block_receive_transactions_to_parent_child_lookup(block_header, receive_transaction_class)
        self.remove_block_child(block_header.parent_hash, block_header.hash)



    def add_block_child(self,
                       parent_block_hash: Hash32,
                       child_block_hash: Hash32) -> None:
        validate_word(parent_block_hash, title="Block_hash")
        validate_word(child_block_hash, title="Block_hash")

        block_children = self.get_block_children(parent_block_hash)


        if block_children is None:
            self.save_block_children(parent_block_hash, [child_block_hash])
        elif child_block_hash in block_children:
            self.logger.debug("tried adding a child block that was already added")
        else:
            block_children.append(child_block_hash)
            self.save_block_children(parent_block_hash, block_children)

    def get_block_children(self, parent_block_hash: Hash32) -> List[Hash32]:
        validate_word(parent_block_hash, title="Block_hash")
        block_children_lookup_key = SchemaV1.make_block_children_lookup_key(parent_block_hash)
        try:
            to_return = rlp.decode(self.db[block_children_lookup_key], sedes=rlp.sedes.FCountableList(hash32), use_list=True)
            if to_return == []:
                return None
            return to_return
        except KeyError:
            return None


    def get_all_descendant_block_hashes(self, block_hash: Hash32) -> List[Hash32]:
        validate_word(block_hash, title="Block_hash")
        descentant_blocks = self._get_all_descendant_block_hashes(block_hash)
        return descentant_blocks

    def _get_all_descendant_block_hashes(self, block_hash: Hash32) -> List[Hash32]:

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
                            block_children: List[Hash32]) -> None:

        validate_word(parent_block_hash, title="Block_hash")
        block_children_lookup_key = SchemaV1.make_block_children_lookup_key(parent_block_hash)
        self.db[block_children_lookup_key] = rlp.encode(block_children, sedes=rlp.sedes.FCountableList(hash32))

    def delete_all_block_children_lookups(self, parent_block_hash: Hash32) -> None:
        validate_word(parent_block_hash, title="Block_hash")
        block_children_lookup_key = SchemaV1.make_block_children_lookup_key(parent_block_hash)
        try:
            del(self.db[block_children_lookup_key])
        except KeyError:
            pass


    def get_block_children_chains(self, block_hash: Hash32, exclude_chains:Set = None) -> Set[Address]:
        validate_word(block_hash, title="Block_hash")
        child_chains = self._get_block_children_chains(block_hash)
        if child_chains is None:
            return set()

        if exclude_chains is not None:
            child_chains = child_chains - exclude_chains
        return child_chains


    def _get_block_children_chains(self, block_hash: Hash32) -> Set[Address]:
        #lookup children
        children = self.get_block_children(block_hash)

        if children == None:
            return set()
        else:
            child_chains = set()
            for child_block_hash in children:
                chain_wallet_address = self.get_chain_wallet_address_for_block_hash(child_block_hash)
                child_chains.add(chain_wallet_address)

                sub_children_chain_wallet_addresses = self._get_block_children_chains(child_block_hash)

                child_chains.update(sub_children_chain_wallet_addresses)
            return child_chains

    #This doesnt include stake from this block
    def get_block_stake_from_children(self, block_hash: Hash32, exclude_chains: Set = None) -> int:
        validate_word(block_hash, title="Block Hash")

        children_chain_wallet_addresses = self.get_block_children_chains(block_hash, exclude_chains)
        origin_wallet_address = self.get_chain_wallet_address_for_block_hash(block_hash)
        try:
            children_chain_wallet_addresses.remove(origin_wallet_address)
        except KeyError:
            pass
        except AttributeError:
            pass

        self.logger.debug(
            "get_block_stake_from_children. children wallet addresses: {}".format(children_chain_wallet_addresses))

        total_stake = 0
        for wallet_address in children_chain_wallet_addresses:
            total_stake += self.get_mature_stake(wallet_address)
        return total_stake

    #this includes children and blocks corresponding to these hashes
    def get_total_block_stake_of_block_hashes(self, block_hashes: List[Hash32], timestamp_for_stake = None) -> int:
        '''
        This will not double count any addresses that the blocks might have in common.
        timestamp_for_stake is the time where stake is calculated. So balances must be COIN_MATURE_TIME_FOR_STAKING time older than timestamp_for_stake
        :param block_hashes:
        :return:
        '''

        children_chain_wallet_addresses = set()
        for block_hash in block_hashes:
            children_chain_wallet_addresses.update(self.get_block_children_chains(block_hash))
            origin_wallet_address = self.get_chain_wallet_address_for_block_hash(block_hash)
            try:
                children_chain_wallet_addresses.add(origin_wallet_address)
            except KeyError:
                pass
            except AttributeError:
                pass

        total_stake = 0
        for wallet_address in children_chain_wallet_addresses:
            total_stake += self.get_mature_stake(wallet_address, timestamp_for_stake)
        return total_stake


    def get_mature_stake(self, wallet_address: Address, timestamp: Timestamp = None,
                         raise_canonical_head_not_found_error: bool = False) -> int:

        if timestamp is None:
            timestamp = int(time.time())

        validate_uint256(timestamp, 'timestamp')
        validate_canonical_address(wallet_address, title="Wallet Address")

        # get account balance
        return self._get_balance_at_time(wallet_address,
                                         timestamp - COIN_MATURE_TIME_FOR_STAKING,
                                         raise_canonical_head_not_found_error=raise_canonical_head_not_found_error)

    def _get_balance_at_time(self, wallet_address: Address, timestamp: Timestamp = None,
                             raise_canonical_head_not_found_error: bool = False) -> int:

        if timestamp is None:
            timestamp = int(time.time())

        try:
            canonical_head = self.get_canonical_head(chain_address=wallet_address)
        except CanonicalHeadNotFound as e:
            if raise_canonical_head_not_found_error:
                raise e
            else:
                return 0

        if canonical_head.timestamp <= timestamp:
            return canonical_head.account_balance
        else:
            if canonical_head.block_number > 0:
                for i in range(canonical_head.block_number - 1, -1, -1):
                    header = self.get_canonical_block_header_by_number(i, wallet_address)
                    if header.timestamp <= timestamp:
                        return header.account_balance

        return 0


    #
    # Historical minimum allowed gas price API for throttling the network
    #
    def save_historical_minimum_gas_price(self, historical_minimum_gas_price: List[List[Union[Timestamp, int]]]) -> None:
        '''
        This takes list of timestamp, gas_price. The timestamps are every minute
        '''
        lookup_key = SchemaV1.make_historical_minimum_gas_price_lookup_key()
        encoded_data = rlp.encode(historical_minimum_gas_price[-MAX_NUM_HISTORICAL_MIN_GAS_PRICE_TO_KEEP:],sedes=rlp.sedes.FCountableList(rlp.sedes.FList([rlp.sedes.f_big_endian_int, rlp.sedes.f_big_endian_int])))
        self.db.set(
            lookup_key,
            encoded_data,
        )


    def load_historical_minimum_gas_price(self, sort:bool = False) -> Optional[List[List[Union[Timestamp, int]]]]:
        '''
        saved as timestamp, min gas price
        '''
        lookup_key = SchemaV1.make_historical_minimum_gas_price_lookup_key()
        try:
            data = rlp.decode(self.db[lookup_key], sedes=rlp.sedes.FCountableList(rlp.sedes.FList([rlp.sedes.f_big_endian_int, rlp.sedes.f_big_endian_int])), use_list = True)
            if sort:
                if len(data) > 0:
                    data.sort()

            return data
        except KeyError:
            return None


    def save_historical_tx_per_centisecond(self, historical_tx_per_centisecond: List[List[int]], de_sparse = True) -> None:
        '''
        This takes list of timestamp, tx_per_centisecond. The timestamps are every minute, tx_per_minute must be an intiger
        this one is naturally a sparse list because some 100 second intervals might have no tx. So we can de_sparse it.
        '''
        if de_sparse:
            historical_tx_per_centisecond = de_sparse_timestamp_item_list(historical_tx_per_centisecond, 100, filler = 0)
        lookup_key = SchemaV1.make_historical_tx_per_centisecond_lookup_key()
        encoded_data = rlp.encode(historical_tx_per_centisecond[-MAX_NUM_HISTORICAL_MIN_GAS_PRICE_TO_KEEP:],sedes=rlp.sedes.FCountableList(rlp.sedes.FList([rlp.sedes.f_big_endian_int, rlp.sedes.f_big_endian_int])))
        self.db.set(
            lookup_key,
            encoded_data,
        )

    def load_historical_tx_per_centisecond(self, sort = False) -> Optional[List[List[int]]]:
        '''
        returns a list of [timestamp, tx/centisecond]
        '''

        lookup_key = SchemaV1.make_historical_tx_per_centisecond_lookup_key()
        try:
            data = rlp.decode(self.db[lookup_key], sedes=rlp.sedes.FCountableList(rlp.sedes.FList([rlp.sedes.f_big_endian_int, rlp.sedes.f_big_endian_int])), use_list=True)
            if sort:
                if len(data) > 0:
                    data.sort()

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
        encoded_data = rlp.encode(historical_tpc_capability[-MAX_NUM_HISTORICAL_MIN_GAS_PRICE_TO_KEEP:],sedes=rlp.sedes.FCountableList(rlp.sedes.FList([rlp.sedes.f_big_endian_int, rlp.sedes.f_big_endian_int])))
        self.db.set(
            lookup_key,
            encoded_data,
        )

    def save_current_historical_network_tpc_capability(self, current_tpc_capability: int) -> None:
        validate_uint256(current_tpc_capability, title="current_tpc_capability")
        existing = self.load_historical_network_tpc_capability()
        current_centisecond = int(time.time()/100) * 100
        if existing is None:
            existing = [[current_centisecond, current_tpc_capability]]
        else:
            existing.append([current_centisecond, current_tpc_capability])
        self.save_historical_network_tpc_capability(existing, de_sparse = True)



    def load_historical_network_tpc_capability(self, sort:bool = False) -> Optional[List[List[Union[Timestamp, int]]]]:
        '''
        Returns a list of [timestamp, transactions per second]
        :param mutable:
        :param sort:
        :return:
        '''
        lookup_key = SchemaV1.make_historical_network_tpc_capability_lookup_key()
        try:
            data = rlp.decode(self.db[lookup_key], sedes=rlp.sedes.FCountableList(rlp.sedes.FList([rlp.sedes.f_big_endian_int, rlp.sedes.f_big_endian_int])), use_list = True)
            if sort:
                if len(data) > 0:
                    data.sort()

            return data
        except KeyError:
            return None


    def _calculate_next_centisecond_minimum_gas_price(self, historical_minimum_allowed_gas: List[List[int]], historical_tx_per_centisecond: List[List[int]], goal_tx_per_centisecond: int) -> int:
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

    def initialize_historical_minimum_gas_price_at_genesis(self, min_gas_price: int, net_tpc_cap: int, tpc: int = None) -> None:
        # we need to initialize the entire additive and fast sync region in time because that is where we check
        # that blocks have enough gas
        current_centisecond = int(time.time()/100) * 100

        historical_minimum_gas_price = []
        historical_tx_per_centisecond = []
        historical_tpc_capability = []

        earliest_required_centisecond = int(time.time()/100)*100-MAX_NUM_HISTORICAL_MIN_GAS_PRICE_TO_KEEP*100

        for timestamp in range(earliest_required_centisecond, current_centisecond+100, 100):
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




    def _recalculate_historical_mimimum_gas_price(self, start_timestamp: Timestamp, end_timestamp: Timestamp = None) -> None:
        #we just have to delete the ones in front of this time and update
        self._delete_newer_historical_mimimum_gas_price(start_timestamp)

        #then update the missing items:
        self._update_historical_mimimum_gas_price(end_timestamp=end_timestamp)

    def _delete_newer_historical_mimimum_gas_price(self, start_timestamp: Timestamp) -> None:
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


    def _update_historical_mimimum_gas_price(self, end_timestamp: Timestamp=None) -> None:
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
                    if len(hist_network_tpc_cap) > 0:
                        timestamps = list(hist_network_tpc_cap.keys())
                        index = bisect.bisect_right(timestamps, timestamp)
                        goal_tx_per_centisecond = hist_network_tpc_cap[timestamps[index-1]]

                    else:
                        raise HistoricalNetworkTPCMissing
                next_centisecond_min_gas_price = self._calculate_next_centisecond_minimum_gas_price(historical_minimum_allowed_gas,
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



    def get_required_block_min_gas_price(self, block_timestamp: Timestamp = None) -> int:
        '''
        it is important that this doesn't run until our blockchain is up to date. If it is run before that,
        it will give the wrong number.
        '''

        if block_timestamp is None:
            block_timestamp = int(time.time())

        centisecond_window = int(block_timestamp/100) * 100


        hist_min_gas_price = self.load_historical_minimum_gas_price()

        if hist_min_gas_price is None or len(hist_min_gas_price) == 0:
            #there is no data for calculating min gas price
            raise HistoricalMinGasPriceError("tried to get required block minimum gas price but historical minimum gas price has not been initialized")

        dict_hist_min_gas_price = dict(hist_min_gas_price)

        #self.logger.debug('get_required_block_min_gas_price, centisecond_window = {}, dict_hist_min_gas_price = {}'.format(centisecond_window, dict_hist_min_gas_price))
        try:
            return dict_hist_min_gas_price[centisecond_window]
        except KeyError:
            pass

        sorted_list = list(hist_min_gas_price)
        sorted_list.sort()
        #if we don't have this centisecond_window, lets return the previous one.
        return sorted_list[-1][1]


    def min_gas_system_initialization_required(self) -> bool:
        test_1 = self.load_historical_minimum_gas_price()
        test_3 = self.load_historical_network_tpc_capability()

        if test_1 is None or test_3 is None:
            return True

        earliest_required_centisecond = int(time.time()) - MAX_NUM_HISTORICAL_MIN_GAS_PRICE_TO_KEEP
        newest_required_centisecond = int(time.time()/100) * 100-100*15
        test_3.sort()


        if test_3[-1][0] < newest_required_centisecond or test_3[0][0] > earliest_required_centisecond:
            return True

        return False

    #
    # Reward bundle persisting
    #

    def persist_reward_bundle(self, reward_bundle: BaseRewardBundle) -> None:
        lookup_key = SchemaV1.make_reward_bundle_hash_lookup_key(reward_bundle.hash)
        self.db[lookup_key] = rlp.encode(reward_bundle, sedes=BaseRewardBundle)

    def get_reward_bundle(self, reward_bundle_hash: Hash32, reward_bundle_class: Type[BaseRewardBundle]) -> BaseRewardBundle:
        validate_is_bytes(reward_bundle_hash, 'reward_bundle_hash')
        lookup_key = SchemaV1.make_reward_bundle_hash_lookup_key(reward_bundle_hash)
        try:
            encoded = self.db[lookup_key]
            return rlp.decode(encoded, sedes=reward_bundle_class)
        except KeyError:
            return reward_bundle_class()

    def get_block_number_of_latest_reward_block(self, chain_address: Address) -> BlockNumber:

        validate_canonical_address(chain_address, title="Wallet Address")

        canonical_head = self.get_canonical_head(chain_address)
        canonical_block_number = canonical_head.block_number

        if canonical_head.reward_hash != BLANK_REWARD_HASH:
            return canonical_block_number

        if canonical_block_number == 0:
            return BlockNumber(0)

        for i in range(canonical_block_number, -1, -1):
            header = self.get_canonical_block_header_by_number(BlockNumber(i), chain_address)
            if header.reward_hash != BLANK_REWARD_HASH:
                return BlockNumber(i)

    def get_latest_reward_block_number(self, wallet_address: Address) -> BlockNumber:
        validate_canonical_address(wallet_address, title="wallet_address")

        key = SchemaV1.make_latest_reward_block_number_lookup(wallet_address)

        try:
            rlp_latest_block_number = self.db.get(key)
        except KeyError:
            rlp_latest_block_number = None

        if rlp_latest_block_number is not None:
            # in order to save some headache elsewhere, if a block is deleted for any reason, we won't reset this number
            # so lets also check to make sure the block with this number has a reward
            block_number = rlp.decode(rlp_latest_block_number, sedes=rlp.sedes.f_big_endian_int)
            try:
                block_header = self.get_canonical_block_header_by_number(block_number, wallet_address)
            except HeaderNotFound:
                # need to find previous reward block and save new one
                latest_reward_block_number = self.get_block_number_of_latest_reward_block(wallet_address)
                self.set_latest_reward_block_number(wallet_address, latest_reward_block_number)
                return latest_reward_block_number

            if block_header.reward_hash == BLANK_REWARD_HASH:
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
