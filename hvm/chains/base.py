from __future__ import absolute_import
import operator
from collections import deque

import functools

from abc import (
    ABCMeta,
    abstractmethod
)
from pprint import pprint

import rlp_cython as rlp
import time
import math
from uuid import UUID
from typing import (  # noqa: F401
    Any,
    Optional,
    Callable,
    cast,
    Dict,
    Generator,
    Iterator,
    Tuple,
    Type,
    TYPE_CHECKING,
    Union,
    List,
    Iterable,
    Set,
)
from hvm.utils.spoof import (
    SpoofTransaction,
)

import logging

from itertools import groupby

from hvm.rlp.receipts import Receipt
from hvm.types import Timestamp

from eth_typing import (
    Address,
    BlockNumber,
    Hash32,
)

from eth_utils import (
    to_tuple,
    to_set,
)


from hvm.db.backends.base import BaseDB
from hvm.db.backends.memory import MemoryDB
from hvm.db.chain import (
    BaseChainDB,
    ChainDB,
)
from hvm.db.journal import (
    JournalDB,
)

from hvm.db.read_only import ReadOnlyDB
from hvm.constants import (
    BLOCK_GAS_LIMIT,
    BLANK_ROOT_HASH,
    NUMBER_OF_HEAD_HASH_TO_SAVE,
    TIME_BETWEEN_HEAD_HASH_SAVE,
    GENESIS_PARENT_HASH,
    BLOCK_TIMESTAMP_FUTURE_ALLOWANCE, BLOCK_TRANSACTION_LIMIT)

from hvm.db.trie import make_trie_root_and_nodes

from hvm import constants
from hvm.estimators import (
    get_gas_estimator,
)
from hvm.exceptions import (
    HeaderNotFound,
    TransactionNotFound,
    ValidationError,
    VMNotFound,
    BlockOnWrongChain,
    CanonicalHeadNotFound,
    CannotCalculateStake,
    NotEnoughTimeBetweenBlocks,
    ReceivableTransactionNotFound,
    TriedImportingGenesisBlock,
    JournalDbNotActivated,
    ReplacingBlocksNotAllowed,
    UnprocessedBlockNotAllowed,
    AppendHistoricalRootHashTooOld,
    HistoricalNetworkTPCMissing,
    HistoricalMinGasPriceError,
    UnprocessedBlockChildIsProcessed,
    ParentNotFound,
    NoChronologicalBlocks,
    RewardProofSenderBlockMissing,
    InvalidHeadRootTimestamp,

    RewardAmountRoundsToZero, TriedDeletingGenesisBlock, NoGenesisBlockPresent, RequiresCodeFromMissingChain)
from eth_keys.exceptions import (
    BadSignature,
)

from hvm.utils.blocks import reorganize_chronological_block_list_for_correct_chronological_order_at_index
from hvm.validation import (
    validate_block_number,
    validate_uint256,
    validate_word,
    validate_vm_configuration,
    validate_canonical_address,
    validate_is_queue_block,
    validate_centisecond_timestamp,
)
from hvm.rlp.blocks import (
    BaseBlock,
    BaseQueueBlock,
)
from hvm.rlp.headers import (
    BlockHeader,
    HeaderParams,
)
from hvm.rlp.transactions import (
    BaseTransaction,
    BaseReceiveTransaction
)
from hvm.utils.db import (
    apply_state_dict,
)
from hvm.utils.datatypes import (
    Configurable,
)
from hvm.utils.headers import (
    compute_gas_limit_bounds,
)
from hvm.utils.hexadecimal import (
    encode_hex,
    decode_hex
)
from hvm.utils.rlp import (
    ensure_imported_block_unchanged,
)

from hvm.db.chain_head import ChainHeadDB
from hvm.db.consensus import ConsensusDB

from eth_keys import keys
from eth_keys.datatypes import(
        BaseKey,
        PublicKey,
        PrivateKey
)

from hvm.utils.numeric import (
    effecient_diff,
    are_items_in_list_equal,
)

from sortedcontainers import (
    SortedList,
    SortedDict,
)
from hvm.rlp.consensus import NodeStakingScore, PeerNodeHealth

from hvm.rlp.accounts import TransactionKey

if TYPE_CHECKING:
    from hvm.vm.base import BaseVM  # noqa: F401


from functools import partial
import asyncio

# Mapping from address to account state.
# 'balance', 'nonce' -> int
# 'code' -> bytes
# 'storage' -> Dict[int, int]
AccountState = Dict[Address, Dict[str, Union[int, bytes, Dict[int, int]]]]

from hvm.db.min_gas import MinGasDB, BaseMinGasDB

exceptions_for_saving_as_unprocessed = (
    ReceivableTransactionNotFound,
    RewardProofSenderBlockMissing,
    RequiresCodeFromMissingChain,
)

class BaseChain(Configurable, metaclass=ABCMeta):
    """
    The base class for all Chain objects
    """
    chain_head_db: ChainHeadDB = None
    chaindb: ChainDB = None
    min_gas_db: MinGasDB = None

    min_gas_db_class = None
    chaindb_class = None  # type: Type[BaseChainDB]
    vm_configuration = None  # type: Tuple[Tuple[int, Type[BaseVM]], ...]
    genesis_wallet_address: Address = None
    genesis_block_timestamp: Timestamp = None
    min_time_between_blocks: int = None

    #
    # Helpers
    #
    @classmethod
    @abstractmethod
    def get_chaindb_class(cls) -> Type[BaseChainDB]:
        raise NotImplementedError("Chain classes must implement this method")

    @classmethod
    @abstractmethod
    def get_min_gas_db_class(cls) -> Type[BaseMinGasDB]:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_consensus_db(self, header: BlockHeader = None, timestamp: Timestamp = None) -> ConsensusDB:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def enable_read_only_db(self) -> None:
        raise NotImplementedError("Chain classes must implement this method")

    #
    # Chain API
    #
    @classmethod
    @abstractmethod
    def from_genesis(cls,
                     base_db: BaseDB,
                     genesis_params: Dict[str, HeaderParams],
                     genesis_state: AccountState=None) -> 'BaseChain':
        raise NotImplementedError("Chain classes must implement this method")

    @classmethod
    @abstractmethod
    def from_genesis_header(cls,
                            base_db: BaseDB,
                            genesis_header: BlockHeader) -> 'BaseChain':
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_chain_at_block_parent(self, block: BaseBlock) -> 'BaseChain':
        raise NotImplementedError("Chain classes must implement this method")

    #
    # VM API
    #
    @classmethod
    def get_vm_configuration(cls) -> Tuple[Tuple[int, Type['BaseVM']], ...]:
        return cls.vm_configuration

    @classmethod
    def get_vm_class(cls, header: BlockHeader) -> Type['BaseVM']:
        """
        Returns the VM instance for the given block number.
        """
        return cls.get_vm_class_for_block_timestamp(header.timestamp)

    @abstractmethod
    def get_vm(self, header: BlockHeader=None, timestamp: Timestamp = None) -> 'BaseVM':
        raise NotImplementedError("Chain classes must implement this method")

    @classmethod
    def get_vm_class_for_block_timestamp(cls, timestamp: int = None) -> Type['BaseVM']:
        """
        Returns the VM class for the given block number.
        """
        if timestamp is None:
            timestamp = int(time.time())
        if cls.vm_configuration is None:
            raise AttributeError("Chain classes must define the VMs in vm_configuration")
        validate_uint256(timestamp)
        for start_timestamp, vm_class in reversed(cls.vm_configuration):
            if timestamp >= start_timestamp:
                return vm_class
        else:
            raise VMNotFound("No vm available for timestamp #{0}".format(timestamp))

    #
    # Header API
    #
    @abstractmethod
    def create_header_from_parent(self,
                                  parent_header: BlockHeader,
                                  **header_params: HeaderParams) -> BlockHeader:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_block_header_by_hash(self, block_hash: Hash32) -> BlockHeader:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_canonical_head(self):
        raise NotImplementedError("Chain classes must implement this method")

    #
    # Block API
    #
    @abstractmethod
    def get_ancestors(self, limit: int, header: BlockHeader=None) -> Iterator[BaseBlock]:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_block_by_hash(self, block_hash: Hash32) -> BaseBlock:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_block_by_header(self, block_header: BlockHeader) -> BaseBlock:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_block_by_number(self, block_number: BlockNumber, wallet_address: Address = None) -> BaseBlock:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_blocks_on_chain(self, start: int, end: int, wallet_address: Address = None) -> List[BaseBlock]:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_all_blocks_on_chain(self, wallet_address: Address = None) -> List[BaseBlock]:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_all_blocks_on_chain_by_head_block_hash(self, chain_head_hash: Hash32) -> List[BaseBlock]:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_blocks_on_chain_up_to_block_hash(self, chain_head_hash: Hash32, start_block_number: int = 0, limit: int = float('inf')) -> List[BaseBlock]:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_block(self) -> BaseBlock:
        raise NotImplementedError("Chain classes must implement this method")


    # @abstractmethod
    # def get_canonical_block_by_number(self, block_number: BlockNumber) -> BaseBlock:
    #     raise NotImplementedError("Chain classes must implement this method")

    # @abstractmethod
    # def get_canonical_block_hash(self, block_number):
    #     raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_all_chronological_blocks_for_window(self, window_timestamp: Timestamp) -> List[BaseBlock]:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def import_current_queue_block(self) -> BaseBlock:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def import_current_queue_block_with_reward(self, node_staking_score_list: List[NodeStakingScore]) -> BaseBlock:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def purge_block_and_all_children_and_set_parent_as_chain_head_by_hash(self, block_hash_to_delete: Hash32) -> None:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def purge_block_and_all_children_and_set_parent_as_chain_head(self, existing_block_header: BlockHeader):
        raise NotImplementedError("Chain classes must implement this method")

    #
    # Chronologically consistent blockchain db API
    #
    @abstractmethod
    def check_block_chronological_consistency(self, block: BaseBlock) -> List[Hash32]:
        raise NotImplementedError("Chain classes must implement this method")
    #
    # Transaction API
    #
    @abstractmethod
    def get_transaction_by_block_hash_and_index(self, block_hash: Hash32, transaction_index: int) -> Union[BaseTransaction, BaseReceiveTransaction]:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_transaction_by_hash(self, tx_hash: Hash32) -> Union[BaseTransaction, BaseReceiveTransaction]:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def create_transaction(self, *args: Any, **kwargs: Any) -> BaseTransaction:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def filter_accounts_with_receivable_transactions(self, chain_addresses: List[Address]) -> List[Address]:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_canonical_transaction(self, transaction_hash: Hash32) -> BaseTransaction:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def populate_queue_block_with_receive_tx(self) -> List[BaseReceiveTransaction]:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_block_receive_transactions_by_hash(
            self,
            block_hash: Hash32) -> List['BaseReceiveTransaction']:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_receive_tx_from_send_tx(self, tx_hash: Hash32) -> Optional['BaseReceiveTransaction']:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_block_send_transactions_by_block_hash(self, block_hash: Hash32) -> List[BaseTransaction]:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def create_receivable_transactions(self) -> List[BaseReceiveTransaction]:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_receivable_transactions(self, address: Address) -> Tuple[List[BaseReceiveTransaction], List[TransactionKey]]:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_current_queue_block_nonce(self) -> int:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def create_and_sign_transaction_for_queue_block(self, *args: Any, **kwargs: Any) -> BaseTransaction:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def create_and_sign_transaction(self, *args: Any, **kwargs: Any) -> BaseTransaction:
        raise NotImplementedError("Chain classes must implement this method")

    #
    # Chronological Chain API
    #
    @abstractmethod
    def try_to_rebuild_chronological_chain_from_historical_root_hashes(self, historical_root_hash_timestamp: Timestamp) -> None:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_block_hashes_that_are_new_for_this_historical_root_hash_timestamp(self, historical_root_hash_timestamp: Timestamp) -> List[Tuple[Timestamp, Hash32]]:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_receivable_transaction_hashes_from_chronological(self, start_timestamp: Timestamp, only_these_addresses = None) -> Tuple[List[Hash32], Set[Address]]:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def initialize_historical_root_hashes_and_chronological_blocks(self, current_window = None, earliest_root_hash = None) -> None:
        raise NotImplementedError("Chain classes must implement this method")

    #
    # Execution API
    #
    @abstractmethod
    def generate_tx_and_get_result(self,
                                   tx_data: bytes,
                                   from_address: Address,
                                   to_address: Address,
                                   at_header: BlockHeader = None,
                                   at_timestamp: Timestamp = None,
                                   ) -> Any:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_transaction_result(
            self,
            transaction: Union[BaseTransaction, SpoofTransaction],
            at_header: BlockHeader = None,
            at_timestamp: Timestamp = None, ) -> bytes:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def estimate_gas(self, transaction: BaseTransaction, at_header: BlockHeader=None) -> int:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def import_block(self, block: BaseBlock, perform_validation: bool=True) -> BaseBlock:
        raise NotImplementedError("Chain classes must implement this method")


    @abstractmethod
    def import_chain(self, block_list: List[BaseBlock], perform_validation: bool=True, save_block_head_hash_timestamp: bool = True, allow_replacement: bool = True) -> None:
        raise NotImplementedError("Chain classes must implement this method")

    # @abstractmethod
    # def import_chronological_block_window(self, block_list: List[BaseBlock], window_start_timestamp: Timestamp,
    #                                       save_block_head_hash_timestamp: bool = True,
    #                                       allow_unprocessed: bool = False) -> None:
    #     raise NotImplementedError("Chain classes must implement this method")



    #
    # Validation API
    #
    @abstractmethod
    def get_allowed_time_of_next_block(self, chain_address: Address = None) -> Timestamp:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def validate_block(self, block: BaseBlock) -> None:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def validate_gaslimit(self, header: BlockHeader) -> None:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def validate_block_specification(self, block) -> bool:
        raise NotImplementedError("Chain classes must implement this method")

    #
    # Stake API
    #
    @abstractmethod
    def get_mature_stake(self, wallet_address: Address = None, raise_canonical_head_not_found_error:bool = False) -> int:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_mature_stake_for_chronological_block_window(self, chronological_block_window_timestamp, timestamp_for_stake):
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_new_block_hash_to_test_peer_node_health(self) -> Hash32:
        raise NotImplementedError("Chain classes must implement this method")

    #
    # Min Block Gas API used for throttling the network
    #
    @abstractmethod
    def re_initialize_historical_minimum_gas_price_at_genesis(self) -> None:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def update_current_network_tpc_capability(self, current_network_tpc_cap: int,
                                              update_min_gas_price: bool = True) -> None:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def update_PID_min_gas_price(self) -> None:
        raise NotImplementedError("Chain classes must implement this method")



    @abstractmethod
    def get_local_tpc_cap(self) -> int:
        raise NotImplementedError("Chain classes must implement this method")

    #
    # Consensus db passthrough with correct db corresponding to timestamp
    #
    @abstractmethod
    def get_signed_peer_score(self, private_key: PrivateKey,
                              network_id: int,
                              peer_wallet_address: Address,
                              after_block_number: BlockNumber = None,
                              ) -> NodeStakingScore:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_signed_peer_score_string_private_key(self,
                                                 private_key_string: bytes,
                                                 peer_wallet_address: Address,
                                                 after_block_number: BlockNumber = None,
                                                 ) -> NodeStakingScore:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def validate_node_staking_score(self,
                                    node_staking_score: NodeStakingScore,
                                    since_block_number: BlockNumber) -> None:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def save_health_request(self, peer_wallet_address: Address, response_time_in_micros: int = float('inf')) -> None:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_current_peer_node_health(self,peer_wallet_address: Address) -> PeerNodeHealth:
        raise NotImplementedError("Chain classes must implement this method")

class Chain(BaseChain):
    """
    A Chain is a combination of one or more VM classes.  Each VM is associated
    with a range of blocks.  The Chain class acts as a wrapper around these other
    VM classes, delegating operations to the appropriate VM depending on the
    current block number.
    """
    raise_errors = False

    logger = logging.getLogger("hvm.chain.chain.Chain")
    header = None  # type: BlockHeader
    network_id = None  # type: int
    gas_estimator = None  # type: Callable
    _journaldb = None
    num_journal_records_for_block_import = 0

    chaindb_class = ChainDB  # type: Type[BaseChainDB]
    chain_head_db_class = ChainHeadDB
    min_gas_db_class = MinGasDB


    _queue_block: BaseQueueBlock = None


    def __init__(self, base_db: BaseDB, wallet_address: Address, private_key: BaseKey=None) -> None:
        if not self.vm_configuration:
            raise ValueError(
                "The Chain class cannot be instantiated with an empty `vm_configuration`"
            )
        else:
            validate_vm_configuration(self.vm_configuration)


        validate_canonical_address(wallet_address, "Wallet Address")

        self.db = base_db
        self.private_key = private_key
        self.wallet_address = wallet_address
        self.chaindb = self.get_chaindb_class()(self.db)
        self.chain_head_db = self.get_chain_head_db_class().load_from_saved_root_hash(self.db)
        self.min_gas_db = self.get_min_gas_db_class()(self.db)

        try:
            self.header = self.create_header_from_parent(self.get_canonical_head())
        except CanonicalHeadNotFound:
            #this is a new block, lets make a genesis block
            # self.logger.debug("Creating new genesis block on chain {}".format(self.wallet_address))
            self.header = self.get_vm_class_for_block_timestamp().create_genesis_block(self.wallet_address).header



        if self.gas_estimator is None:
            self.gas_estimator = get_gas_estimator()  # type: ignore

    def reinitialize(self):
        self.__init__(self.db, self.wallet_address, self.private_key)

    def set_new_wallet_address(self, wallet_address: Address, private_key: BaseKey=None):
        self.logger.debug('setting new wallet address')
        self.wallet_address = wallet_address
        self.private_key = private_key
        self.reinitialize()

    @property
    def queue_block(self):
        if self._queue_block is None:
            self._queue_block = self.get_queue_block()
        return self._queue_block

    @queue_block.setter
    def queue_block(self,val:BaseQueueBlock):
        self._queue_block = val

    @property
    def min_time_between_blocks(self):
        vm = self.get_vm(timestamp=Timestamp(int(time.time())))
        min_allowed_time_between_blocks = vm.min_time_between_blocks
        return min_allowed_time_between_blocks

    # @property
    # def consensus_db(self, header: BlockHeader = None, timestamp: Timestamp = None):
    #     # gets the consensus db corresponding to the block timestamp
    #
    #     return self.get_vm(header, timestamp).consensus_db

    def get_consensus_db(self, header: BlockHeader = None, timestamp: Timestamp = None) -> ConsensusDB:
        # gets the consensus db corresponding to the block timestamp

        return self.get_vm(header, timestamp).consensus_db

    #
    # Global Record and discard API
    #

    def enable_read_only_db(self) -> None:
        if not isinstance(self.db, ReadOnlyDB):
            self.base_db = self.db
            self.db = ReadOnlyDB(self.base_db)
            self.reinitialize()


    def enable_journal_db(self):
        if self._journaldb is None:
            self.base_db = self.db
            self._journaldb = JournalDB(self.base_db)
            #we keep the name self.db so that all of the functions still work, but at this point it is a journaldb.
            self.db = self._journaldb
            #reinitialize to ensure chain and chain_head_db have the new journaldb
            self.reinitialize()

    def disable_journal_db(self):
        if self._journaldb is not None:
            self.db = self.base_db
            self._journaldb = None

            #reinitialize to ensure chain and chain_head_db have the new journaldb
            self.reinitialize()

    def record_journal(self) -> UUID:
        if self._journaldb is not None:
            return (self._journaldb.record())
        else:
            raise JournalDbNotActivated()

    def discard_journal(self, changeset: UUID) -> None:
        if self._journaldb is not None:
            db_changeset = changeset
            self._journaldb.discard(db_changeset)
        else:
            raise JournalDbNotActivated()

    def commit_journal(self, changeset: UUID) -> None:
        if self._journaldb is not None:
            db_changeset = changeset
            self._journaldb.commit(db_changeset)
        else:
            raise JournalDbNotActivated()

    def persist_journal(self) -> None:
        if self._journaldb is not None:
            self._journaldb.persist()
        else:
            raise JournalDbNotActivated()


    #
    # Helpers
    #
    @classmethod
    def get_chaindb_class(cls) -> Type[BaseChainDB]:
        if cls.chaindb_class is None:
            raise AttributeError("`chaindb_class` not set")
        return cls.chaindb_class

    @classmethod
    def get_min_gas_db_class(cls) -> Type[BaseChainDB]:
        if cls.min_gas_db_class is None:
            raise AttributeError("`min_gas_db_class` not set")
        return cls.min_gas_db_class

    @classmethod
    def get_chain_head_db_class(cls) -> Type[ChainHeadDB]:
        if cls.chain_head_db_class is None:
            raise AttributeError("`chain_head_db class` not set")
        return cls.chain_head_db_class


    @classmethod
    def get_genesis_wallet_address(cls) -> Address:
        if cls.genesis_wallet_address is None:
            raise AttributeError("`genesis_wallet_address` not set")
        return cls.genesis_wallet_address


    #
    # Chain API
    #


    @classmethod
    def create_genesis_header(cls,
                     base_db: BaseDB,
                     wallet_address: Address,
                     private_key: BaseKey,
                     genesis_params: Dict[str, HeaderParams],
                     genesis_state: AccountState=None,
                     ) -> 'BaseChain':

        genesis_vm_class = cls.get_vm_class_for_block_timestamp()

        account_db = genesis_vm_class.get_state_class().get_account_db_class()(base_db)

        if genesis_state is None:
            genesis_state = {}

        # mutation
        account_db = apply_state_dict(account_db, genesis_state)
        account_db.persist(save_account_hash = True, wallet_address = wallet_address)
        genesis_params['account_hash'] = account_db.get_account_hash(wallet_address)
        genesis_header = BlockHeader(**genesis_params)

        signed_genesis_header = genesis_header.get_signed(private_key, cls.network_id)
        chaindb = cls.get_chaindb_class()(base_db)
        chaindb.persist_header(signed_genesis_header)
        return signed_genesis_header

    @classmethod
    def from_genesis(cls,
                     base_db: BaseDB,
                     wallet_address: Address,
                     genesis_params: Dict[str, HeaderParams],
                     genesis_state: AccountState,
                     private_key: BaseKey = None
                     ) -> 'BaseChain':
        """
        Initializes the Chain from a genesis state.
        """

        genesis_vm_class = cls.get_vm_class_for_block_timestamp(genesis_params['timestamp'])

        account_db = genesis_vm_class.get_state_class().get_account_db_class()(
            base_db
        )

        if genesis_state is None:
            genesis_state = {}

        # mutation
        account_db = apply_state_dict(account_db, genesis_state)
        account_db.persist(save_account_hash = True, wallet_address = cls.genesis_wallet_address)

        genesis_header = BlockHeader(**genesis_params)
        return cls.from_genesis_header(base_db, wallet_address = wallet_address, private_key = private_key, genesis_header = genesis_header)


    @classmethod
    def from_genesis_header(cls,
                            base_db: BaseDB,
                            wallet_address: Address,
                            genesis_header: BlockHeader,
                            private_key: BaseKey,
                            ) -> 'BaseChain':
        """
        Initializes the chain from the genesis header.
        """

        chaindb = cls.get_chaindb_class()(base_db)
        chaindb.persist_header(genesis_header)

        chain_head_db = cls.get_chain_head_db_class()(base_db)

        #window_for_this_block = math.ceil((genesis_header.timestamp+1)/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
        window_for_this_block = int(genesis_header.timestamp / TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE + TIME_BETWEEN_HEAD_HASH_SAVE
        chain_head_db.set_chain_head_hash(cls.genesis_wallet_address, genesis_header.hash)
        chain_head_db.initialize_historical_root_hashes(chain_head_db.root_hash, window_for_this_block)
        chain_head_db.persist(save_current_root_hash = True)
        #chain_head_db.add_block_hash_to_chronological_window(genesis_header.hash, genesis_header.timestamp)

        return cls(base_db, wallet_address = wallet_address, private_key=private_key)


    def get_chain_at_block_parent(self, block: BaseBlock) -> BaseChain:
        """
        Returns a `Chain` instance with the given block's parent at the chain head.
        """
        try:
            parent_header = self.get_block_header_by_hash(block.header.parent_hash)
        except HeaderNotFound:
            raise ValidationError("Parent ({0}) of block {1} not found".format(
                block.header.parent_hash,
                block.header.hash
            ))

        init_header = self.create_header_from_parent(parent_header)
        return type(self)(self.chaindb.db, self.wallet_address, self.private_key, init_header)



    #
    # VM API
    #
    def get_vm(self, header: BlockHeader=None, timestamp: Timestamp = None) -> 'BaseVM':
        """
        Returns the VM instance for the given block timestamp. Or if timestamp is given, gets the vm for that timestamp
        """
        if header is not None and timestamp is not None:
            raise ValueError("Cannot specify header and timestamp for get_vm(). Only one is allowed.")

        if header is None or header == self.header:
            header = self.header
            if timestamp is not None:
                header = header.copy(timestamp = timestamp)

            vm_class = self.get_vm_class_for_block_timestamp(header.timestamp)
            return vm_class(header=header,
                           chaindb=self.chaindb,
                           network_id=self.network_id)
        else:
            vm_class = self.get_vm_class_for_block_timestamp(header.timestamp)
            return vm_class(header=header,
                            chaindb=self.chaindb,
                            network_id=self.network_id)


    #
    # Header API
    #
    def create_header_from_parent(self, parent_header, **header_params):
        """
        Passthrough helper to the VM class of the block descending from the
        given header.
        """
        return self.get_vm_class_for_block_timestamp().create_header_from_parent(parent_header, **header_params)

    def get_block_header_by_hash(self, block_hash: Hash32) -> BlockHeader:
        """
        Returns the requested block header as specified by block hash.

        Raises BlockNotFound if there's no block header with the given hash in the db.
        """
        validate_word(block_hash, title="Block Hash")
        return self.chaindb.get_block_header_by_hash(block_hash)

    def get_canonical_head(self, chain_address = None):
        """
        Returns the block header at the canonical chain head.

        Raises CanonicalHeadNotFound if there's no head defined for the canonical chain.
        """
        if chain_address is not None:
            return self.chaindb.get_canonical_head(chain_address)
        else:
            return self.chaindb.get_canonical_head(self.wallet_address)


    #
    # Block API
    #
    def get_genesis_block_hash(self) -> Hash32:
        return self.chaindb.get_canonical_block_hash(block_number = BlockNumber(0),
                                                     chain_address= self.genesis_wallet_address)

    @to_tuple
    def get_ancestors(self, limit: int, header: BlockHeader=None) -> Iterator[BaseBlock]:
        """
        Return `limit` number of ancestor blocks from the current canonical head.
        """
        if header is None:
            header = self.header
        lower_limit = max(header.block_number - limit, 0)
        for n in reversed(range(lower_limit, header.block_number)):
            yield self.get_block_by_number(BlockNumber(n), header.chain_address)

    def get_block_by_hash(self, block_hash: Hash32) -> BaseBlock:

        block_header = self.get_block_header_by_hash(block_hash)

        return self.get_block_by_header(block_header)




    def get_block_by_header(self, block_header: BlockHeader) -> BaseBlock:
        """
        Returns the requested block as specified by the block header.
        """
        block_class = self.get_vm_class_for_block_timestamp(block_header.timestamp).get_block_class()

        send_transactions = self.chaindb.get_block_transactions(block_header, block_class.transaction_class)

        receive_transactions = self.chaindb.get_block_receive_transactions(block_header,block_class.receive_transaction_class)

        reward_bundle = self.chaindb.get_reward_bundle(block_header.reward_hash, block_class.reward_bundle_class)

        output_block = block_class(block_header, send_transactions, receive_transactions, reward_bundle)

        return output_block

    def get_block_by_number(self, block_number: BlockNumber, chain_address: Address = None) -> BaseBlock:
        if chain_address is None:
            chain_address = self.wallet_address

        block_hash = self.chaindb.get_canonical_block_hash(block_number, chain_address)
        return self.get_block_by_hash(block_hash)

    def get_blocks_on_chain(self, start: int, end: int, chain_address: Address = None) -> List[BaseBlock]:
        if chain_address is None:
            chain_address = self.wallet_address

        if end == 0:
            canonical_head_header = self.get_canonical_head(chain_address=chain_address)
            head_block_number = canonical_head_header.block_number
            end = head_block_number + 1

        blocks = []
        for block_number in range(start, end):
            try:
                new_block = self.get_block_by_number(BlockNumber(block_number), chain_address)
                blocks.append(new_block)
            except HeaderNotFound:
                break

        return blocks

    def get_all_blocks_on_chain(self, chain_address: Address = None) -> List[BaseBlock]:
        if chain_address is None:
            chain_address = self.wallet_address

        canonical_head_header = self.get_canonical_head(chain_address=chain_address)
        head_block_number = canonical_head_header.block_number

        return self.get_blocks_on_chain(0, head_block_number + 1, chain_address=chain_address)

    def get_all_blocks_on_chain_by_head_block_hash(self, chain_head_hash: Hash32) -> List[BaseBlock]:
        chain_head_header = self.get_block_header_by_hash(chain_head_hash)
        chain_address = chain_head_header.chain_address
        return self.get_all_blocks_on_chain(chain_address)

    def get_blocks_on_chain_up_to_block_hash(self, chain_head_hash: Hash32, start_block_number: int = 0, limit: int = float('inf')) -> List[BaseBlock]:
        chain_head_header = self.get_block_header_by_hash(chain_head_hash)
        to_block_number = chain_head_header.block_number
        if to_block_number > (start_block_number + limit):
            to_block_number = (start_block_number + limit)

        chain_address = chain_head_header.chain_address

        return self.get_blocks_on_chain(start_block_number, to_block_number + 1, chain_address)


    def get_block(self) -> BaseBlock:
        """
        Returns the current TIP block.
        """
        return self.get_vm().block

    def get_queue_block(self) -> BaseBlock:
        """
        Returns the current TIP block.
        """
        return self.get_vm().queue_block

    # def get_block_by_hash(self, block_hash: Hash32) -> BaseBlock:
    #     """
    #     Returns the requested block as specified by block hash.
    #     """
    #     validate_word(block_hash, title="Block Hash")
    #     block_header = self.get_block_header_by_hash(block_hash)
    #     return self.get_block_by_header(block_header)



    # def get_canonical_block_by_number(self, block_number: BlockNumber) -> BaseBlock:
    #     """
    #     Returns the block with the given number in the canonical chain.
    #
    #     Raises BlockNotFound if there's no block with the given number in the
    #     canonical chain.
    #     """
    #     validate_uint256(block_number, title="Block Number")
    #     return self.get_block_by_hash(self.chaindb.get_canonical_block_hash(block_number))
    #
    # def get_canonical_block_hash(self, block_number: BlockNumber) -> Hash32:
    #     """
    #     Returns the block hash with the given number in the canonical chain.
    #
    #     Raises BlockNotFound if there's no block with the given number in the
    #     canonical chain.
    #     """
    #     return self.chaindb.get_canonical_block_hash(block_number)


    #
    # Queueblock API
    #
    def add_transaction_to_queue_block(self, transaction) -> None:

        validate_is_queue_block(self.queue_block, title='self.queue_block')

        if isinstance(transaction, BaseTransaction):
            if not self.queue_block.contains_transaction(transaction):
                self.queue_block = self.queue_block.add_transaction(transaction)
            else:
                self.logger.debug("found transaction in queueblock already, not adding again")
        else:
            if not self.queue_block.contains_receive_transaction(transaction):
                self.queue_block = self.queue_block.add_receive_transaction(transaction)
            else:
                self.logger.debug("found receive transaction in queueblock already, not adding again")

    def add_transactions_to_queue_block(self, transactions) -> None:
        if not isinstance(transactions, list):
            self.add_transaction_to_queue_block(transactions)
            #self.logger.debug("tx_nonce after adding transaction = {}".format(self.queue_block.current_tx_nonce))
        else:
            for tx in transactions:
                self.add_transaction_to_queue_block(tx)

    def sign_queue_block(self, *args: Any, **kwargs: Any) -> BaseQueueBlock:
        """
        Passthrough helper to the current VM class.
        """
        return self.get_vm().sign_queue_block(*args, **kwargs)

    def sign_header(self, *args: Any, **kwargs: Any) -> BlockHeader:
        """
        Passthrough helper to the current VM class.
        """
        return self.get_vm().sign_header(*args, **kwargs)


    #
    # Transaction API
    #

    def filter_accounts_with_receivable_transactions(self, chain_addresses: List[Address]) -> List[Address]:
        return self.get_vm().state.filter_accounts_with_receivable_transactions(chain_addresses)

    def get_canonical_transaction(self, transaction_hash: Hash32) -> BaseTransaction:
        """
        Returns the requested transaction as specified by the transaction hash
        from the canonical chain.

        Raises TransactionNotFound if no transaction with the specified hash is
        found in the main chain.
        """
        (block_hash, index, is_receive) = self.chaindb.get_transaction_index(transaction_hash)

        block_header = self.get_block_header_by_hash(block_hash)

        vm = self.get_vm_class_for_block_timestamp(block_header.timestamp)

        transaction = self.chaindb.get_transaction_by_hash(transaction_hash,
                                                            vm.get_transaction_class(),
                                                            vm.get_receive_transaction_class())


        if transaction.hash == transaction_hash:
            return transaction
        else:
            raise TransactionNotFound("Found transaction {} instead of {} in block {} at {}".format(
                encode_hex(transaction.hash),
                encode_hex(transaction_hash),
                block_hash,
                index,
            ))

    @functools.lru_cache(maxsize=32)
    def get_transaction_by_block_hash_and_index(self, block_hash: Hash32, transaction_index: int) -> Union[BaseTransaction, BaseReceiveTransaction]:
        num_send_transactions = self.chaindb.get_number_of_send_tx_in_block(block_hash)
        header = self.chaindb.get_block_header_by_hash(block_hash)
        vm = self.get_vm(header=header)
        if transaction_index >= num_send_transactions:
            # receive transaction
            transaction_index = transaction_index - num_send_transactions
            tx = self.chaindb.get_receive_transaction_by_index_and_block_hash(block_hash=block_hash,
                                                                              transaction_index=transaction_index,
                                                                              transaction_class=vm.get_receive_transaction_class())
        else:
            # send transaction
            tx = self.chaindb.get_transaction_by_index_and_block_hash(block_hash=block_hash,
                                                                      transaction_index=transaction_index,
                                                                      transaction_class=vm.get_transaction_class())

        return tx

    @functools.lru_cache(maxsize=32)
    def get_transaction_by_hash(self, tx_hash: Hash32) -> Union[BaseTransaction, BaseReceiveTransaction]:
        block_hash, index, is_receive = self.chaindb.get_transaction_index(tx_hash)
        header = self.chaindb.get_block_header_by_hash(block_hash)
        vm = self.get_vm(header=header)
        transaction = self.chaindb.get_transaction_by_hash(tx_hash, vm.get_transaction_class(), vm.get_receive_transaction_class())
        return transaction

    def create_transaction(self, *args: Any, **kwargs: Any) -> BaseTransaction:
        """
        Passthrough helper to the current VM class.
        """
        return self.get_vm().create_transaction(*args, **kwargs)


    def create_and_sign_transaction(self, *args: Any, **kwargs: Any) -> BaseTransaction:
        if self.private_key is None:
            raise ValueError("Cannot sign transaction because private key not provided for chain instantiation")

        transaction = self.create_transaction(*args, **kwargs)
        signed_transaction = transaction.get_signed(self.private_key, self.network_id)
        return signed_transaction

    def create_and_sign_transaction_for_queue_block(self, *args: Any, **kwargs: Any) -> BaseTransaction:
        if 'nonce' not in kwargs or kwargs['nonce'] is None:
            kwargs['nonce'] = self.get_current_queue_block_nonce()

        transaction = self.create_and_sign_transaction(*args, **kwargs)

        self.add_transactions_to_queue_block(transaction)
        return transaction

    def get_current_queue_block_nonce(self) -> int:
        if self.queue_block is None or self.queue_block.current_tx_nonce is None:
            tx_nonce = self.get_vm().state.account_db.get_nonce(self.wallet_address)
        else:
            tx_nonce =self.queue_block.current_tx_nonce
        return tx_nonce

    def create_receive_transaction(self, *args: Any, **kwargs: Any) -> BaseReceiveTransaction:
        """
        Passthrough helper to the current VM class.
        """
        return self.get_vm().create_receive_transaction(*args, **kwargs)

    def get_receivable_transactions(self, address: Address) -> Tuple[List[BaseReceiveTransaction], List[TransactionKey]]:
        #from hvm.rlp_templates.accounts import TransactionKey
        tx_keys = self.get_vm().state.account_db.get_receivable_transactions(address)
        if len(tx_keys) == 0:
            return [], []
        transactions = []
        for tx_key in tx_keys:
            tx = self.get_canonical_transaction(tx_key.transaction_hash)
            transactions.append(tx)
        return transactions, tx_keys

    def create_receivable_transactions(self) -> List[BaseReceiveTransaction]:
        vm = self.get_vm()
        tx_keys = vm.state.account_db.get_receivable_transactions(self.wallet_address)
        if len(tx_keys) == 0:
            return []

        receive_transactions = []
        for tx_key in tx_keys:
            #find out if it is a receive or a refund
            block_hash, index, is_receive = self.chaindb.get_transaction_index(tx_key.transaction_hash)
            refund_amount = vm.state.account_db.get_refund_amount_for_transaction(tx_key.transaction_hash)

            re_tx = self.get_vm().create_receive_transaction(
                    sender_block_hash = tx_key.sender_block_hash,
                    send_transaction_hash=tx_key.transaction_hash,
                    is_refund=is_receive,
                    refund_amount=refund_amount,
                    )

            receive_transactions.append(re_tx)
        return receive_transactions

    def populate_queue_block_with_receive_tx(self) -> List[BaseReceiveTransaction]:
        receive_tx = self.create_receivable_transactions()
        num_send_transactions = len(self.queue_block.transactions)
        max_allowed_receive_transactions = BLOCK_TRANSACTION_LIMIT - num_send_transactions - 1
        self.add_transactions_to_queue_block(receive_tx[:max_allowed_receive_transactions])
        return receive_tx

    def get_block_receive_transactions_by_hash(
            self,
            block_hash: Hash32) -> List['BaseReceiveTransaction']:

        block_header = self.get_block_header_by_hash(block_hash)
        vm = self.get_vm(header = block_header)
        receive_transaction_class = vm.get_block_class().receive_transaction_class
        receive_transactions = self.chaindb.get_block_receive_transactions(header = block_header, transaction_class = receive_transaction_class)
        return receive_transactions

    def get_receive_tx_from_send_tx(self, tx_hash: Hash32) -> Optional['BaseReceiveTransaction']:
        block_hash, index, is_receive = self.chaindb.get_transaction_index(tx_hash)
        if is_receive:
            raise ValidationError("The provided tx hash is not for a send transaction")

        send_transaction = self.get_canonical_transaction(tx_hash)
        block_children = self.chaindb.get_block_children(block_hash)
        if block_children is not None:
            block_children_on_correct_chain = [child_hash for child_hash in block_children
                                               if self.chaindb.get_chain_wallet_address_for_block_hash(child_hash) == send_transaction.to]

            for block_hash in block_children_on_correct_chain:
                receive_transactions = self.get_block_receive_transactions_by_hash(block_hash)
                for receive_tx in receive_transactions:
                    if receive_tx.send_transaction_hash == tx_hash:
                        return receive_tx

        return None

    def get_transaction_by_index_and_block_hash(self, block_hash: Hash32, transaction_index: int) -> Union[BaseTransaction, BaseReceiveTransaction]:
        header = self.chaindb.get_block_header_by_hash(block_hash)
        vm = self.get_vm(header=header)

        self.chaindb.get_transaction_by_index_and_block_hash()

        self.chaindb.get_transaction_by_index_and_block_hash(
            block_hash,
            transaction_index,
            vm.get_transaction_class(),
        )

    def get_block_send_transactions_by_block_hash(self, block_hash: Hash32) -> List[BaseTransaction]:
        header = self.chaindb.get_block_header_by_hash(block_hash)

        block_class = self.get_vm_class_for_block_timestamp(header.timestamp).get_block_class()

        return self.chaindb.get_block_transactions(header, block_class.transaction_class)
    #
    # Chronological Chain api
    #

    def try_to_rebuild_chronological_chain_from_historical_root_hashes(self, historical_root_hash_timestamp: Timestamp) -> None:
        try:
            correct_chronological_block_window = self.get_block_hashes_that_are_new_for_this_historical_root_hash_timestamp(historical_root_hash_timestamp)
            self.chain_head_db.save_chronological_block_window(correct_chronological_block_window, historical_root_hash_timestamp-TIME_BETWEEN_HEAD_HASH_SAVE)
        except InvalidHeadRootTimestamp:
            pass

    def get_block_hashes_that_are_new_for_this_historical_root_hash_timestamp(self, historical_root_hash_timestamp: Timestamp) -> List[Tuple[Timestamp, Hash32]]:
        '''
        This is a time consuming function that gets all of the blocks that are new in this root hash that didn't exist in the base root hash.
        :param timestamp:
        :return:
        '''

        block_window_start = historical_root_hash_timestamp - TIME_BETWEEN_HEAD_HASH_SAVE

        base_root_hash = self.chain_head_db.get_historical_root_hash(block_window_start)
        new_root_hash = self.chain_head_db.get_historical_root_hash(historical_root_hash_timestamp)

        if base_root_hash == new_root_hash:
            return None

        if base_root_hash is None or new_root_hash is None:
            raise InvalidHeadRootTimestamp(
                "Could not load block hashes for this historical_root_hash_timestamp because we don't have a root hash for this window or the previous window.")

        base_head_block_hashes = set(self.chain_head_db.get_head_block_hashes(base_root_hash))
        new_head_block_hashes = set(self.chain_head_db.get_head_block_hashes(new_root_hash))
        diff_head_block_hashes = new_head_block_hashes - base_head_block_hashes

        chronological_block_hash_timestamps = []
        # now we have to run down each chain until we get to a block that is older than block_window_start
        for head_block_hash in diff_head_block_hashes:
            header = self.chaindb.get_block_header_by_hash(head_block_hash)
            chronological_block_hash_timestamps.append([header.timestamp, head_block_hash])

            while True:
                if header.parent_hash == GENESIS_PARENT_HASH:
                    break
                try:
                    header = self.chaindb.get_block_header_by_hash(header.parent_hash)
                except HeaderNotFound:
                    break

                if header.timestamp < block_window_start:
                    break

                chronological_block_hash_timestamps.append([header.timestamp, header.hash])

        assert len(chronological_block_hash_timestamps) > 0

        chronological_block_hash_timestamps.sort()
        return chronological_block_hash_timestamps




    def get_receivable_transaction_hashes_from_chronological(self, start_timestamp: Timestamp, only_these_addresses = None) -> Tuple[List[Hash32], Set[Address]]:
        # return list of transactions, and set of accounts with receivable transactions

        self.chain_head_db.load_saved_root_hash()
        earliest_root_hash = self.chain_head_db.earliest_window + TIME_BETWEEN_HEAD_HASH_SAVE
        window_start_timestamp = int(start_timestamp / TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
        
        if window_start_timestamp < earliest_root_hash:
            raise ValidationError("get_receivable_transactions_from_chronological start_timestamp is older than the oldest chronological window")

        current_window = self.chain_head_db.current_window

        receivable_transactions = []
        wallet_addresses = set()

        vm_now = self.get_vm()

        for chronological_block_window_timestamp in range(window_start_timestamp, current_window + TIME_BETWEEN_HEAD_HASH_SAVE, TIME_BETWEEN_HEAD_HASH_SAVE):
            chronological_block_hash_timestamps = self.chain_head_db.load_chronological_block_window(Timestamp(chronological_block_window_timestamp))
            if chronological_block_hash_timestamps is not None:
                for timestamp_block_hash in chronological_block_hash_timestamps:
                    if timestamp_block_hash[0] >= start_timestamp:
                        block_send_transactions = self.get_block_send_transactions_by_block_hash(timestamp_block_hash[1])

                        for send_transaction in block_send_transactions:
                            if send_transaction.to not in wallet_addresses:
                                if only_these_addresses is None or send_transaction.to in only_these_addresses:
                                    receivable_transaction_keys_for_this_account = vm_now.state.account_db.get_receivable_transactions(send_transaction.to)
                                    if len(receivable_transaction_keys_for_this_account) > 0:
                                        receivable_transactions.extend([key.transaction_hash for key in receivable_transaction_keys_for_this_account])
                                        wallet_addresses.add(send_transaction.to)

        return receivable_transactions, wallet_addresses

        
        
        
    
    def initialize_historical_root_hashes_and_chronological_blocks(self, current_window = None, earliest_root_hash = None) -> None:
        '''
        This function rebuilds all historical root hashes, and chronological blocks, from the blockchain database. It starts with the saved root hash and works backwards.
        This function needs to be run from chain because it requires chain_head_db and chaindb.
        :return:
        '''

        self.chain_head_db.load_saved_root_hash()
        if current_window is None:
            current_window = self.chain_head_db.current_window
            historical_root_hashes = self.chain_head_db.get_historical_root_hashes()
            newest_historical_root_hash_timestamp = historical_root_hashes[-1][0]
            if newest_historical_root_hash_timestamp > current_window:
                current_window = newest_historical_root_hash_timestamp

        if earliest_root_hash is None:
            earliest_root_hash = self.chain_head_db.earliest_window

        #TIME_BETWEEN_HEAD_HASH_SAVE

        # the saved
        # 1) iterate down the root hash times
        # 2) create new chain_head_db with memorydb
        # 3) go through each chain and any blocks newer than the timestamp, save to chronological window.
        # 4) when you reach a block less than the timestamp, set it as chain head in the new memory based chain_head_db
        # 5) get the root hash
        # 6) set this root hash in the real chain_head_db at the correct timestamp.

        # A chronological block window holds all of the blocks starting at its timestamp, going to timestamp + TIME_BETWEEN_HEAD_HASH_SAVE
        # A historical root hash is the root hash at the given timestamp, so it includes all blocks earlier than that timestamp.
        self.logger.debug("Rebuilding chronological block windows")
        # us a journaldb so that it doesnt write changes to the database.
        #temp_chain_head_db = self.get_chain_head_db_class()(MemoryDB())
        #temp_chain_head_db = self.get_chain_head_db_class().load_from_saved_root_hash(JournalDB(self.db))

        # Delete all historical root hashes first to make sure we dont have any stragglers
        self.chain_head_db.delete_historical_root_hashes()

        # We are iterating over historical root hash times. Chronological block hash times are one behind this
        for current_historical_root_hash_timestamp in range(current_window, earliest_root_hash-TIME_BETWEEN_HEAD_HASH_SAVE, -TIME_BETWEEN_HEAD_HASH_SAVE):
            if current_historical_root_hash_timestamp < self.genesis_block_timestamp:
                break

            head_block_hashes = self.chain_head_db.get_head_block_hashes_list()

            # Delete any existing chronological blocks
            self.chain_head_db.delete_chronological_block_window(current_historical_root_hash_timestamp)

            # iterate over all chains
            for head_block_hash in head_block_hashes:
                current_block_hash = head_block_hash
                # now iterate over blocks in chain
                while True:
                    current_header = self.chaindb.get_block_header_by_hash(current_block_hash)
                    if current_header.timestamp >= current_historical_root_hash_timestamp:
                        # add it to chronological block window in the real chain head db
                        self.chain_head_db.add_block_hash_to_chronological_window(current_header.hash, current_header.timestamp)
                    else:
                        # The block is older than the timestamp. Set it as the chain head block hash in our temp chain head db
                        self.chain_head_db.set_chain_head_hash(current_header.chain_address, current_header.hash)
                        break
                    if current_header.parent_hash == GENESIS_PARENT_HASH:
                        # we reached the end of the chain
                        self.chain_head_db.delete_chain_head_hash(current_header.chain_address)
                        break
                    # set the current block to the parent so we move down the chain
                    current_block_hash = current_header.parent_hash

            # Now that we have gone through all chains, and removed any blocks newer than this timestamp, the root hash in the
            # temp chain head db is the correct one for this historical root hash timestamp.
            self.chain_head_db.save_single_historical_root_hash(self.chain_head_db.root_hash, Timestamp(current_historical_root_hash_timestamp))

        self.chain_head_db.persist()

        # finally, lets load the saved root hash again so we are up to date.
        self.chain_head_db.load_saved_root_hash()

    #
    # Execution API
    #
    def generate_tx_and_get_result(self,
                                   tx_data: bytes,
                                   from_address: Address,
                                   to_address: Address,
                                   at_header: BlockHeader = None,
                                   at_timestamp: Timestamp = None,
                                   **kwargs,
                                   ) -> Any:

        vm = self.get_vm(header=at_header, timestamp=at_timestamp)
        tx = vm.generate_transaction_for_single_computation(tx_data = tx_data,
                                                    from_address = from_address,
                                                    to_address = to_address,
                                                    **kwargs,
                                                    )


        return self.get_transaction_result(tx)


    def get_transaction_result(
            self,
            transaction: Union[BaseTransaction, SpoofTransaction],
            at_header: BlockHeader = None,
            at_timestamp: Timestamp = None,) -> bytes:

        if at_header is not None and at_timestamp is not None:
            raise ValidationError("Cannot specify at_header and at_timestamp together.")

        vm = self.get_vm(header = at_header, timestamp = at_timestamp)
        vm.min_time_between_blocks = 0
        computation = vm.compute_single_transaction(transaction)

        computation.raise_if_error()
        return computation.output


    def estimate_gas(self, transaction: BaseTransaction, at_header: BlockHeader=None) -> int:
        """
        Returns an estimation of the amount of gas the given transaction will
        use if executed on top of the block specified by the given header.
        """
        if at_header is None:
            at_header = self.get_canonical_head()
        with self.get_vm(at_header).state_in_temp_block() as state:
            return self.gas_estimator(state, transaction)



    def validate_time_from_genesis_block(self,block):
        if not block.is_genesis:
            #first make sure enough time has passed since genesis. We need at least TIME_BETWEEN_HEAD_HASH_SAVE since genesis so that the
            # genesis historical root hash only contains the genesis chain.
            if block.header.timestamp < (self.genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE):
                raise NotEnoughTimeBetweenBlocks("Not enough time has passed since the genesis block. Must wait at least {} seconds after genesis block. "
                                                 "This block timestamp is {}, genesis block timestamp is {}.".format(TIME_BETWEEN_HEAD_HASH_SAVE, block.header.timestamp, self.genesis_block_timestamp))

        return



    #
    # Reverting account functions
    #
    def clear_account_while_keeping_receivable_transactions(self, chain_address: Address) -> None:
        try:
            #get current receivable transactions from vm for newest block. But add it to receivable transactions for vm of block reverting to.
            newest_header = self.chaindb.get_canonical_head(chain_address)
            revert_header = self.chaindb.get_canonical_block_header_by_number(BlockNumber(0), chain_address)

            newest_vm = self.get_vm(header=newest_header)
            revert_vm = self.get_vm(header=revert_header)

            current_receivable_transactions = newest_vm.state.account_db.get_receivable_transactions(chain_address)

            revert_vm.state.clear_account_keep_receivable_transactions_and_persist(chain_address, current_receivable_transactions)

        except HeaderNotFound:
            pass
        
    def revert_account_while_keeping_receivable_transactions(self, new_chain_head_header: BlockHeader) -> None:
        try:
            #get current receivable transactions from vm for newest block. But add it to receivable transactions for vm of block reverting to.
            newest_header = self.chaindb.get_canonical_head(new_chain_head_header.chain_address)
            
            newest_vm = self.get_vm(header=newest_header)
            revert_vm = self.get_vm(header=new_chain_head_header)

            current_receivable_transactions = newest_vm.state.account_db.get_receivable_transactions(new_chain_head_header.chain_address)

            revert_vm.state.revert_account_to_hash_keep_receivable_transactions_and_persist(new_chain_head_header.account_hash, new_chain_head_header.chain_address, current_receivable_transactions)

        except HeaderNotFound:
            pass

    def revert_account_to_block_parent_and_add_receivable_transactions_from_block(self, header_to_revert: BlockHeader) -> None:
        # We don't load receivable transactions from the VM. Instead, we go through the transactions in the block. This is because
        # the receivable transactions in the saved account for the block may not be accurate anymore.
        vm = self.get_vm(header=header_to_revert)
        vm.reverse_pending_transactions(header_to_revert)
        vm.state.account_db.persist()

    #
    # Reverting block functions
    #

    def delete_canonical_chain(self, chain_address: Address, save_block_head_hash_timestamp:bool = True) -> None:
        self.logger.debug("delete_canonical_chain. Chain address {}".format(encode_hex(chain_address)))
        
        self.clear_account_while_keeping_receivable_transactions(chain_address)
        self.chain_head_db.delete_chain(chain_address, save_block_head_hash_timestamp)
        self.chaindb.delete_canonical_chain(chain_address)


    def set_parent_as_canonical_head(self, existing_block_header: BlockHeader, save_block_head_hash_timestamp:bool = True) -> None:
        block_parent_header = self.chaindb.get_block_header_by_hash(existing_block_header.parent_hash)

        self.logger.debug("Setting new block as canonical head after reverting blocks. Chain address {}, header hash {}".format(encode_hex(existing_block_header.chain_address), encode_hex(block_parent_header.hash)))

        self.revert_account_while_keeping_receivable_transactions(block_parent_header)

        if save_block_head_hash_timestamp:
            self.chain_head_db.add_block_hash_to_timestamp(block_parent_header.chain_address, block_parent_header.hash, block_parent_header.timestamp)


        self.chain_head_db.set_chain_head_hash(block_parent_header.chain_address, block_parent_header.hash)
        self.chaindb._set_as_canonical_chain_head(block_parent_header)



    def revert_block(self, descendant_block_hash: Hash32) -> None:
        self.logger.debug('Reverting block with hash {}'.format(encode_hex(descendant_block_hash)))
        descendant_block_header = self.chaindb.get_block_header_by_hash(descendant_block_hash)

        self.revert_account_to_block_parent_and_add_receivable_transactions_from_block(descendant_block_header)
        self.chain_head_db.delete_block_hash_from_chronological_window(descendant_block_hash, descendant_block_header.timestamp)
        self.chaindb.remove_block_from_all_parent_child_lookups(descendant_block_header, self.get_vm(header=descendant_block_header).get_block_class().receive_transaction_class)
        self.chaindb.delete_all_block_children_lookups(descendant_block_hash)
        self.revert_block_chronological_consistency_lookups(descendant_block_hash)

        # remove the block from the canonical chain. This must be done last because reversing the pending transactions requires that it
        # is still in the canonical chain to look up transactions
        self.chaindb.delete_block_from_canonical_chain(descendant_block_hash)
        #self.chaindb.save_unprocessed_block_lookup(descendant_block_hash)



    def revert_block_chronological_consistency_lookups(self, block_hash: Hash32) -> None:
        # check to see if there are any reward type 2 proofs. Then loop through each one to revert inconsistency lookups
        block_header = self.chaindb.get_block_header_by_hash(block_hash)
        block_class = self.get_vm_class_for_block_timestamp(block_header.timestamp).get_block_class()
        reward_bundle = self.chaindb.get_reward_bundle(block_header.reward_hash, block_class.reward_bundle_class)
        chronological_consistency_key = [block_header.timestamp, block_header.hash]

        for proof in reward_bundle.reward_type_2.proof:
            # timestamp, block hash of block responsible

            sender_chain_header = self.chaindb.get_block_header_by_hash(proof.head_hash_of_sender_chain)
            # The chronological consistency restrictions are placed on the block on top of the one giving the proof.
            block_number_with_restrictions = sender_chain_header.block_number + 1
            self.chaindb.delete_block_consistency_key(sender_chain_header.chain_address, block_number_with_restrictions, chronological_consistency_key)

    def purge_block_and_all_children_and_set_parent_as_chain_head_by_hash(self, block_hash_to_delete: Hash32, save_block_head_hash_timestamp: bool = True) -> None:

        genesis_block_hash = self.chaindb.get_canonical_block_hash(BlockNumber(0), self.genesis_wallet_address)
        if block_hash_to_delete == genesis_block_hash:
            raise TriedDeletingGenesisBlock("Attempted to delete genesis block. This is not allowed.")

        block_header_to_delete = self.chaindb.get_block_header_by_hash(block_hash_to_delete)
        self.purge_block_and_all_children_and_set_parent_as_chain_head(block_header_to_delete, save_block_head_hash_timestamp)


    def purge_block_and_all_children_and_set_parent_as_chain_head(self, existing_block_header: BlockHeader, save_block_head_hash_timestamp: bool = True) -> None:
        # First make sure it is actually in the canonical chain. If not, then we don't have anything to do.
        if self.chaindb.is_in_canonical_chain(existing_block_header.hash):
            if existing_block_header.block_number == 0:
                self.delete_canonical_chain(existing_block_header.chain_address, save_block_head_hash_timestamp)
            else:
                #set the parent block as the new canonical head, and handle all the data for that
                self.set_parent_as_canonical_head(existing_block_header, save_block_head_hash_timestamp)

            #1) delete chronological transactions, delete everything from chronological root hashes, delete children lookups
            all_descendant_block_hashes = self.chaindb.get_all_descendant_block_hashes(existing_block_header.hash)

            #first set all of the new chain heads and all the data that goes along with them
            if all_descendant_block_hashes is not None:
                for descendant_block_hash in all_descendant_block_hashes:
                    if not self.chaindb.is_block_unprocessed(descendant_block_hash):
                        descendant_block_header = self.chaindb.get_block_header_by_hash(descendant_block_hash)

                        if descendant_block_header.parent_hash not in all_descendant_block_hashes:
                            #this is the new head of a chain. set it as the new head for chronological root hashes
                            #except for children in this chain, because it will be off by 1 block. we already set this earlier

                            if descendant_block_header.chain_address != existing_block_header.chain_address:
                                if descendant_block_header.block_number == 0:
                                    self.delete_canonical_chain(descendant_block_header.chain_address, save_block_head_hash_timestamp)
                                else:
                                    self.set_parent_as_canonical_head(descendant_block_header, save_block_head_hash_timestamp)


                #now we know what the new heads are, so we can deal with the rest of the descendants
                for descendant_block_hash in all_descendant_block_hashes:
                    #here, since we are already going through all children, we don't need this function to purge children as well
                    if self.chaindb.is_block_unprocessed(descendant_block_hash):
                        self.purge_unprocessed_block(descendant_block_hash, purge_children_too = False)
                    else:
                        self.revert_block(descendant_block_hash)

            self.revert_block(existing_block_header.hash)

            #persist changes

            self.chain_head_db.persist(True)

            self.reinitialize()


    def purge_unprocessed_block(self, block_hash, purge_children_too = True):
        '''
        Deletes all unprocessed block lookups, and unprocessed children lookups for this block and all children blocks.
        Todo: delete saved block header, and saved transaction tries for each block as well
        '''
        self.logger.debug("purging unprocessed block")
        if purge_children_too:
            self.logger.debug("purging unprocessed children")
            if self.chaindb.has_unprocessed_children(block_hash):
                self.logger.debug("HAS UNPROCESSED CHILDREN BLOCKS")
                children_block_hashes = self.chaindb.get_block_children(block_hash)
                if children_block_hashes != None:
                    for child_block_hash in children_block_hashes:
                        #this includes the child in this actual chain as well as children from send transactions.
                        if not self.chaindb.is_block_unprocessed(child_block_hash):
                            raise UnprocessedBlockChildIsProcessed("In process of deleting children of unprocessed block, and found one that is processed. This should never happen")

                        else:

                            self.purge_unprocessed_block(child_block_hash)

        try:
            block = self.get_block_by_hash(block_hash)
            chain = encode_hex(block.header.chain_address)
            self.logger.debug("deleting unprocessed child block number {} on chain {}".format(block.number, chain))
            self.chaindb.remove_block_from_unprocessed(block)
        except HeaderNotFound:
            pass



    #
    # def import_chronological_block_window(self, block_list: List[BaseBlock], window_start_timestamp: Timestamp, save_block_head_hash_timestamp:bool = True, allow_unprocessed:bool =False) -> None:
    #     validate_uint256(window_start_timestamp, title='timestamp')
    #
    #     if block_list is None or len(block_list) == 0:
    #         return
    #
    #     #if we are given a block that is not one of the two allowed classes, try converting it.
    #     if len(block_list) > 0 and not isinstance(block_list[0], self.get_vm(timestamp = block_list[0].header.timestamp).get_block_class()):
    #         self.logger.debug("converting chain to correct class")
    #         corrected_block_list = []
    #         for block in block_list:
    #             corrected_block = self.get_vm(timestamp = block.header.timestamp).convert_block_to_correct_class(block)
    #             corrected_block_list.append(corrected_block)
    #         block_list = corrected_block_list
    #
    #
    #     #first we delete any blocks we have in the same window that are not in the new block list
    #     local_chronological_timestamp_block_window = self.chain_head_db.load_chronological_block_window(window_start_timestamp)
    #
    #     if local_chronological_timestamp_block_window is not None:
    #         local_block_hash_list = [x[1] for x in local_chronological_timestamp_block_window]
    #
    #         new_block_hash_list = [block.hash for block in block_list]
    #
    #         block_hashes_to_delete = effecient_diff(new_block_hash_list, local_block_hash_list)
    #         if len(block_hashes_to_delete) > 0:
    #             self.logger.debug("deleting existing blocks in chronological window {}".format(block_hashes_to_delete))
    #
    #         for block_hash_to_delete in block_hashes_to_delete:
    #             self.purge_block_and_all_children_and_set_parent_as_chain_head_by_hash(block_hash_to_delete)
    #
    #     if len(block_list) > 0:
    #         self.logger.debug("starting block import for chronological block window")
    #         #if block list is empty, load the local historical root hashes and delete them all
    #         for i in range(len(block_list)):
    #             # Reset this after each block imports
    #             blocks_that_have_been_reorganized = set()
    #             wallet_address = block_list[i].header.chain_address
    #             while True:
    #                 try:
    #                     self.import_block(block_list[i], wallet_address = wallet_address, save_block_head_hash_timestamp = save_block_head_hash_timestamp, allow_unprocessed=allow_unprocessed)
    #                     break
    #                 except (UnprocessedBlockNotAllowed, ParentNotFound) as e:
    #                     # Because of the timestamps being in seconds, there may be multiple blocks that depend on each other
    #                     # with the same timestamp, and they could be out of order.  So we attempt to reorganize the blocks
    #                     # and import again. If it fails again we will raise the exception.
    #                     if block_list[i].header.hash in blocks_that_have_been_reorganized:
    #                         self.logger.debug("Already tried reorganizing this block.")
    #                         raise e
    #                     self.logger.debug("Attempting to reorganize chronological window for import")
    #                     blocks_that_have_been_reorganized.add(block_list[i].header.hash)
    #                     block_list = reorganize_chronological_block_list_for_correct_chronological_order_at_index(block_list, i, self.logger)
    #
    #
    #     else:
    #         self.logger.debug("importing an empty chronological window. going to make sure we have a saved historical root hash")
    #         historical_root_hashes = self.chain_head_db.get_historical_root_hashes()
    #         if historical_root_hashes is not None:
    #             #historical_root_hashes_dict = dict(historical_root_hashes)
    #             #if it does exist, make sure it is the same as the last one. if not, then delete all newer
    #             try:
    #                 self.chain_head_db.propogate_previous_historical_root_hash_to_timestamp(window_start_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE)
    #             except AppendHistoricalRootHashTooOld:
    #                 self.logger.debug("Tried to propogate the previous historical root hash but there was none. This shouldn't happen")
    #     #self.logger.debug("historical root hashes after chronological block import {}".format(self.chain_head_db.get_historical_root_hashes()))

    def import_chain(self, block_list: List[BaseBlock], perform_validation: bool=True, save_block_head_hash_timestamp: bool = True, allow_replacement: bool = True) -> None:
        if len(block_list) > 0:
            self.logger.debug("importing chain")
            #if we are given a block that is not one of the two allowed classes, try converting it.
            if not isinstance(block_list[0], self.get_vm(timestamp = block_list[0].header.timestamp).get_block_class()):
                self.logger.debug("converting chain to correct class")
                corrected_block_list = []
                for block in block_list:
                    corrected_block = self.get_vm(timestamp = block.header.timestamp).convert_block_to_correct_class(block)
                    corrected_block_list.append(corrected_block)
                block_list = corrected_block_list


            wallet_address = block_list[0].header.chain_address
            for block in block_list:
                self.import_block(block,
                                  perform_validation = perform_validation,
                                  save_block_head_hash_timestamp = save_block_head_hash_timestamp,
                                  wallet_address = wallet_address,
                                  allow_replacement = allow_replacement)

            # If we started with a longer chain, and all the imported blocks match ours, our chain will remain longer even after importing the new one.
            # To fix this, we need to delete any blocks of ours that is longer in length then this chain that we are importing

            # First make sure the whole chain imported correctly. If not, then we don't need to do anything

            try:
                local_canonical_head = self.chaindb.get_canonical_head(wallet_address)
                imported_canonical_head = block_list[-1].header
                #self.logger.debug("imported chain head hash {}. actual chain head hash {}".format(encode_hex(imported_canonical_head.hash), encode_hex(local_canonical_head.hash)))
                if imported_canonical_head.block_number < local_canonical_head.block_number:
                    if self.chaindb.is_in_canonical_chain(imported_canonical_head.hash):
                        # Our chain is the same as the imported one, but we have some extra blocks on top. In this case, we would like to prune our chain
                        # to match the imported one.
                        # We only need to purge the next block after the imported chain. The vm will automatically purge all children
                        self.logger.debug("After importing a chain, our local chain is identical except with additional blocks on top. We will prune the top blocks to bring"
                                          " our chain in line with the imported one.")
                        block_number_to_purge = imported_canonical_head.block_number + 1
                        hash_to_purge = self.chaindb.get_canonical_block_hash(BlockNumber(block_number_to_purge), wallet_address)
                        self.purge_block_and_all_children_and_set_parent_as_chain_head_by_hash(hash_to_purge, save_block_head_hash_timestamp)
            except CanonicalHeadNotFound:
                pass


    from hvm.utils.profile import profile
    @profile(sortby='cumulative')
    def import_block_with_profiler(self, *args, **kwargs):
        self.import_block(*args, **kwargs)


    def import_block(self, block: BaseBlock,
                     perform_validation: bool=True,
                     save_block_head_hash_timestamp = True,
                     wallet_address = None,
                     allow_unprocessed = True,
                     allow_replacement = True,
                     ensure_block_unchanged:bool = True,
                     microblock_origin: bool = False) -> BaseBlock:

        #we handle replacing blocks here
        #this includes deleting any blocks that it might be replacing
        #then we start the journal db
        #then within _import_block, it can commit the journal
        #but we wont persist until it gets out here again.
        wallet_address = block.header.chain_address
        # we need to re-initialize the chain for the new wallet address.
        if wallet_address != self.wallet_address:
            self.logger.debug("Changing to chain with wallet address {}".format(encode_hex(wallet_address)))
            self.set_new_wallet_address(wallet_address=wallet_address)

        # If is microblock_origin, then this block is a newly created block from the RPC. This means we are fully synced
        # and if this block depends on another block that doesnt exist, we shouldn't save it as unprocessed. Just reject it instead.
        if microblock_origin:
            allow_unprocessed = False

        journal_enabled = False

        #if we are given a block that is not one of the two allowed classes, try converting it.
        #There is no reason why this should be a queueblock, because a queueblock would never come over the network, it
        #it always generated locally, and should have the correct class.
        if not isinstance(block, self.get_vm(timestamp = block.header.timestamp).get_block_class()):
            self.logger.debug("converting block to correct class")
            block = self.get_vm(timestamp = block.header.timestamp).convert_block_to_correct_class(block)

        if isinstance(block, self.get_vm(timestamp = block.header.timestamp).get_queue_block_class()):
            # Set the queue block timestamp to now, when it is being imported.
            block = block.copy(header=block.header.copy(timestamp=int(time.time())))
            allow_unprocessed = False
        else:
            if block.header.chain_address == self.genesis_wallet_address and block.header.block_number == 0:
                try:
                    our_genesis_hash = self.chaindb.get_canonical_block_header_by_number(BlockNumber(0), self.genesis_wallet_address).hash
                except HeaderNotFound:
                    raise NoGenesisBlockPresent("Tried importing a block, but we have no genesis block loaded. Need to load a genesis block first.")

                if block.header.hash == our_genesis_hash:
                    return block
                else:
                    raise ValidationError("Tried to import a new genesis block on the genesis chain. This is not allowed.")


        block.validate_has_content()

        #if we are adding to the top of the chain, or beyond, we need to check for unprocessed blocks
        #handle deleting any unprocessed blocks that will be replaced.
        if block.number >= self.header.block_number:

            existing_unprocessed_block_hash = self.chaindb.get_unprocessed_block_hash_by_block_number(self.wallet_address, block.number)

            if (existing_unprocessed_block_hash != block.hash) and (existing_unprocessed_block_hash is not None):
                if not allow_replacement:
                    raise ReplacingBlocksNotAllowed("Attempted to replace an unprocessed block.")

                #check to make sure the parent matches the one we have
                if block.number != 0:
#                    if block.number == self.header.block_number:
#                        existing_parent_hash = self.chaindb.get_canonical_head_hash(self.wallet_address)
#                    else:
                    existing_unprocessed_parent_hash = self.chaindb.get_unprocessed_block_hash_by_block_number(self.wallet_address, block.number-1)

                    if existing_unprocessed_parent_hash is not None:
                        if block.header.parent_hash != existing_unprocessed_parent_hash:
                            raise ParentNotFound("Parent is unprocessed. Parent hash = {}, this hash = {}".format(
                                encode_hex(existing_unprocessed_parent_hash), encode_hex(block.header.parent_hash)))

                    else:
                        try:
                            existing_canonical_parent_hash = self.chaindb.get_canonical_block_header_by_number(block.header.block_number-1, block.header.chain_address)
                            if block.header.parent_hash != existing_canonical_parent_hash:
                                raise ParentNotFound("Parent is canonical. Parent hash = {}, this hash = {}".format(
                                    encode_hex(existing_canonical_parent_hash), encode_hex(block.header.parent_hash)))
                        except HeaderNotFound:
                            pass

                #lets delete the unprocessed block, and its children, then import
                self.enable_journal_db()
                journal_record = self.record_journal()
                journal_enabled = True

                self.purge_unprocessed_block(existing_unprocessed_block_hash)


        #check to see if this is the same hash that was already saved as unprocessed
        if block.number > self.header.block_number:
            #check that the parent hash matches what we have.
            existing_parent_hash = self.chaindb.get_unprocessed_block_hash_by_block_number(self.wallet_address, block.number-1)
            #we can allow this for unprocessed blocks as long as we have the parent in our database
            if existing_parent_hash == block.header.parent_hash:
                if block.hash == self.chaindb.get_unprocessed_block_hash_by_block_number(self.wallet_address, block.number):
                    #we already imported this one
                    return_block = block
                else:
                    #save as unprocessed
                    if not allow_unprocessed:
                        raise UnprocessedBlockNotAllowed()
                    self.logger.debug("Saving block as unprocessed because parent on this chain is unprocessed")
                    return_block = self.save_block_as_unprocessed(block)

                if journal_enabled:
                    self.logger.debug('commiting journal')
                    self.commit_journal(journal_record)
                    self.persist_journal()
                    self.disable_journal_db()

                return return_block

            else:
                raise ParentNotFound('Parent is unprocessed 2')


        #now, if it is the head of the chain, lets make sure the parent hash is correct.
        if block.number == self.header.block_number and block.number != 0:
            if block.header.parent_hash != self.chaindb.get_canonical_head_hash(chain_address= self.wallet_address):
                raise ParentNotFound("Block is at the head of the chain")


        if block.number < self.header.block_number:
            if not allow_replacement:
                raise ReplacingBlocksNotAllowed("Attempted to replace a canonical block")


            self.logger.debug("went into block replacing mode")
            self.logger.debug("block.number = {}, self.header.block_number = {}".format(block.number,self.header.block_number))
            self.logger.debug("this chains wallet address = {}, this block's sender = {}".format(encode_hex(self.wallet_address), encode_hex(block.sender)))


            #check to see if we can load the existing canonical block
            existing_block_header = self.chaindb.get_canonical_block_header_by_number(block.number, self.wallet_address)

            if existing_block_header.hash == block.header.hash:
                self.logger.debug("tried to import a block that has a hash that matches the local block. no import required.")
                return block
            else:
                if not journal_enabled:
                    self.enable_journal_db()
                    journal_record = self.record_journal()
                    journal_enabled = True

                self.purge_block_and_all_children_and_set_parent_as_chain_head(existing_block_header, save_block_head_hash_timestamp = save_block_head_hash_timestamp)

        #check to see if this block is chronologically inconsistent - usually due to reward block that used proof from this chain
        block_hashes_leading_to_inconsistency = self.check_block_chronological_consistency(block)
        if len(block_hashes_leading_to_inconsistency) > 0:
            if not allow_replacement:
                raise ReplacingBlocksNotAllowed("Attempted to import chronologically inconsistent block. Block hashes leading to inconsistency = {}.".format([encode_hex(x) for x in block_hashes_leading_to_inconsistency]))
            else:
                # revert all of the blocks leading to the inconsistency.
                if not journal_enabled:
                    self.enable_journal_db()
                    journal_record = self.record_journal()
                    journal_enabled = True

                for block_hash in block_hashes_leading_to_inconsistency:
                    self.logger.debug("Purging block {} to preserve chronological consistency".format(encode_hex(block_hash)))
                    block_header = self.chaindb.get_block_header_by_hash(block_hash)
                    # This should be impossible, but lets double check that none of these blocks are on the same chain as this block
                    if block_header.chain_address == block.header.chain_address:
                        raise Exception("Tried to revert chronologically inconsistent block on this same chain. This should never happen...")
                    self.purge_block_and_all_children_and_set_parent_as_chain_head(block_header, save_block_head_hash_timestamp = save_block_head_hash_timestamp)
        try:
            return_block = self._import_block(block = block,
                                              perform_validation = perform_validation,
                                              save_block_head_hash_timestamp = save_block_head_hash_timestamp,
                                              allow_unprocessed = allow_unprocessed,
                                              ensure_block_unchanged= ensure_block_unchanged,
                                              microblock_origin = microblock_origin)

            # handle importing unprocessed blocks here because doing it recursively results in maximum recursion depth exceeded error
            if not self.chaindb.is_block_unprocessed(return_block.hash):
                self.logger.debug("Checking to see if block has unprocessed children")
                self.import_all_unprocessed_descendants(return_block.hash,
                                                        perform_validation= True,
                                                        save_block_head_hash_timestamp = save_block_head_hash_timestamp,
                                                        allow_unprocessed = True)

        except Exception as e:
            if journal_enabled:
                self.logger.debug('discarding journal')
                self.discard_journal(journal_record)
                self.disable_journal_db()
            raise e

        if journal_enabled:
            self.logger.debug('commiting journal')
            self.commit_journal(journal_record)
            self.persist_journal()
            self.disable_journal_db()

        return return_block


    def _import_block(self, block: BaseBlock,
                      perform_validation: bool=True,
                      save_block_head_hash_timestamp = True,
                      allow_unprocessed = True,
                      ensure_block_unchanged: bool = True,
                      microblock_origin: bool = False) -> BaseBlock:
        """
        Imports a complete block.
        """

        self.logger.debug("importing block {} with number {}".format(block.__repr__(), block.number))


        if block.header.timestamp > int(time.time() + BLOCK_TIMESTAMP_FUTURE_ALLOWANCE):
            raise ValidationError("The block header timestamp is to far into the future to be allowed. Block header timestamp {}. Max allowed timestamp {}".format(block.header.timestamp,int(time.time() + BLOCK_TIMESTAMP_FUTURE_ALLOWANCE)))

        self.validate_time_from_genesis_block(block)



        if isinstance(block, self.get_vm(timestamp = block.header.timestamp).get_queue_block_class()):
            # If it was a queueblock, then the header will have changed after importing
            perform_validation = False
            ensure_block_unchanged = False
            queue_block = True
        else:
            queue_block = False

        # this part checks to make sure the parent exists
        if not self.chaindb.is_block_unprocessed(block.header.parent_hash):

            try:
                # Load all of the send transactions that any receive transactions reference, and add them to the receive transaction objects.
                # Needs to be done here, and not in the VM because the send transactions could be from blocks that require a different VM
                self.populate_referenced_transactions(block.receive_transactions)

                vm = self.get_vm(timestamp = block.header.timestamp)
                self.logger.debug("importing block with vm {}".format(vm.__repr__()))
                if queue_block:
                    imported_block = vm.import_block(block, private_key = self.private_key)
                else:
                    imported_block = vm.import_block(block)


                # Validate the imported block.
                if ensure_block_unchanged:
                    if microblock_origin:
                        # this started out as a microblock. So we only ensure the microblock fields are unchanged.
                        self.logger.debug('ensuring block unchanged. microblock correction')
                        corrected_micro_block = block.copy(header = block.header.copy(
                            receipt_root = imported_block.header.receipt_root,
                            bloom = imported_block.header.bloom,
                            gas_limit = imported_block.header.gas_limit,
                            gas_used = imported_block.header.gas_used,
                            account_hash = imported_block.header.account_hash,
                            account_balance = imported_block.header.account_balance,
                        ))

                        ensure_imported_block_unchanged(imported_block, corrected_micro_block)
                    else:
                        self.logger.debug('ensuring block unchanged')
                        ensure_imported_block_unchanged(imported_block, block)
                else:
                    self.logger.debug('Not checking block for changes.')
                if perform_validation:
                    self.validate_block(imported_block)


                #self.chain_head_db.set_chain_head_hash(self.wallet_address, imported_block.header.hash)

                if save_block_head_hash_timestamp:
                    self.chain_head_db.add_block_hash_to_chronological_window(imported_block.header.hash, imported_block.header.timestamp)
                    self.chain_head_db.add_block_hash_to_timestamp(imported_block.header.chain_address, imported_block.hash, imported_block.header.timestamp)


                self.chain_head_db.set_chain_head_hash(imported_block.header.chain_address, imported_block.header.hash)
                self.chain_head_db.persist(True)
                self.chaindb.persist_block(imported_block)
                vm.state.account_db.persist(save_account_hash = True, wallet_address = self.wallet_address)


                #here we must delete the unprocessed lookup before importing children
                #because the children cannot be imported if their chain parent is unprocessed.
                #but we cannot delete the lookup for unprocessed children yet.
                self.chaindb.remove_block_from_unprocessed(imported_block)

                # Add chronological consistency lookups
                self.save_block_chronological_consistency_lookups(imported_block)

                try:
                    self.header = self.create_header_from_parent(self.get_canonical_head())
                except CanonicalHeadNotFound:
                    self.header = self.get_vm_class_for_block_timestamp().create_genesis_block(self.wallet_address).header

                self.queue_block = None
                self.logger.debug(
                    'IMPORTED_BLOCK: number %s | hash %s',
                    imported_block.number,
                    encode_hex(imported_block.hash),
                )

                # Make sure our wallet address hasn't magically changed
                if self.wallet_address != imported_block.header.chain_address:
                    raise ValidationError("Attempted to import a block onto the wrong chain.")

                return_block = imported_block


            except exceptions_for_saving_as_unprocessed as e:
                if not allow_unprocessed:
                    raise UnprocessedBlockNotAllowed()

                self.logger.debug("Saving block as unprocessed because of {} error: {}".format(e.__class__.__name__, e))
                if isinstance(e, RequiresCodeFromMissingChain):
                    return_block = self.save_block_as_unprocessed(block, e.code_address)
                else:
                    return_block = self.save_block_as_unprocessed(block)
                if self.raise_errors:
                    raise e


        else:
            if not allow_unprocessed:
                raise UnprocessedBlockNotAllowed()
            self.logger.debug("Saving block as unprocessed because parent on this chain is unprocessed")
            return_block = self.save_block_as_unprocessed(block)


        return return_block


    def populate_referenced_transactions(self, receive_transactions: List[BaseReceiveTransaction]) -> List[BaseReceiveTransaction]:
        # This function goes through the receive transactions and loads all of the transactions that sent to them, then adds them to the receive transaction object.
        for i in range(len(receive_transactions)):
            current_transaction = receive_transactions[i]
            try:
                while True:
                    header = self.chaindb.get_block_header_by_hash(current_transaction.sender_block_hash)
                    vm_class = self.get_vm_class_for_block_timestamp(header.timestamp)
                    transaction_class = vm_class.get_transaction_class()
                    receive_transaction_class = vm_class.get_receive_transaction_class()
                    referenced_transaction = self.chaindb.get_transaction_by_hash(current_transaction.send_transaction_hash, transaction_class, receive_transaction_class)
                    current_transaction.referenced_send_transaction = referenced_transaction

                    # This referenced transaction could be another receive transaction. This occurs for refund transactions. If it is, populate its reference transaction too.
                    # Continue this chain until we get to a send transaction.
                    if current_transaction.is_refund:
                        current_transaction = referenced_transaction
                    else:
                        break

            except (HeaderNotFound, TransactionNotFound):
                # Raise this now so that we can save it as unprocessed before trying to impor
                raise ReceivableTransactionNotFound

        return receive_transactions

    def import_all_unprocessed_descendants(self, block_hash, *args, **kwargs):
        # 1) get unprocessed children
        # 2) loop through and import
        # 3) if child imports, add their unprocessed children to list, and delete that block from unprocessed
        # 4) if list of unprocessed children has 0 length, break
        # need to step one level at a time. We use a queue to achieve this effect. It won't get to the next level
        # until it finishes all of the blocks on this level. So it goes one level at a time.
        if self.chaindb.has_unprocessed_children(block_hash):
            self.logger.debug("HAS UNPROCESSED BLOCKS")
            # try to import all children
            children_block_hashes = self.chaindb.get_block_children(block_hash)
            if children_block_hashes != None:
                block_hashes_to_import = deque(children_block_hashes)
                # iterate over children
                while True:
                    # remove from right side
                    current_block_hash_to_import = block_hashes_to_import.pop()
                    if self.chaindb.is_block_unprocessed(current_block_hash_to_import):
                        self.logger.debug("importing child block")
                        try:
                            child_block = self.get_block_by_hash(current_block_hash_to_import)
                            if child_block.header.chain_address != self.wallet_address:
                                #self.logger.debug("Changing to chain with wallet address {}".format(encode_hex(child_block.header.chain_address)))
                                self.set_new_wallet_address(wallet_address=child_block.header.chain_address)
                            self._import_block(child_block, *args, **kwargs)


                            #if the block imported, add its children the the deque
                            if not self.chaindb.is_block_unprocessed(current_block_hash_to_import):
                                # it imported successfully
                                if self.chaindb.has_unprocessed_children(current_block_hash_to_import):
                                    children_block_hashes = self.chaindb.get_block_children(current_block_hash_to_import)
                                    if children_block_hashes != None:
                                        block_hashes_to_import.extendleft(children_block_hashes)

                                # we have queued up its children to be imported. Assuming exceptions don't occur, we can remove this block from the unprocessed children lookup.
                                self.chaindb.delete_unprocessed_children_blocks_lookup(current_block_hash_to_import)

                        except Exception as e:
                            self.logger.error("Tried to import an unprocessed child block and got this error {}. Going to delete it from unprocessed blocks.".format(e))
                            self.chaindb.delete_unprocessed_children_blocks_lookup(current_block_hash_to_import)


                    if len(block_hashes_to_import) == 0:
                        return

        self.chaindb.delete_unprocessed_children_blocks_lookup(block_hash)

    def save_block_chronological_consistency_lookups(self, block: BaseBlock) -> None:
        '''
        We need to require that the proof sender chain doesn't add a block after their claimed chain_head_hash, and the timestamp of this block being imported.
        :param block:
        :return:
        '''
        block_header = block.header
        reward_bundle = self.chaindb.get_reward_bundle(block_header.reward_hash, block.reward_bundle_class)
        chronological_consistency_key = [block_header.timestamp, block_header.hash]

        for proof in reward_bundle.reward_type_2.proof:
            # timestamp, block hash of block responsible

            sender_chain_header = self.chaindb.get_block_header_by_hash(proof.head_hash_of_sender_chain)
            # The chronological consistency restrictions are placed on the block on top of the one giving the proof.
            block_number_with_restrictions = sender_chain_header.block_number + 1
            self.logger.debug("saving chronological consistency lookup for chain {}, block {}, timestamp {}".format(encode_hex(sender_chain_header.chain_address), block_number_with_restrictions, block_header.timestamp))
            self.chaindb.add_block_consistency_key(sender_chain_header.chain_address, block_number_with_restrictions, chronological_consistency_key)

    def save_block_as_unprocessed(self, block, computation_call_parent_dependency: Hash32 = None):
        #if it is already saved as unprocesessed, do nothing
        if self.chaindb.is_block_unprocessed(block.hash):
            return block

        #before adding to unprocessed blocks, make sure the receive transactions are valid
        # for receive_transaction in block.receive_transactions:
        #     #there must be at least 1 to get this far
        #     receive_transaction.validate()

        #now we add it to unprocessed blocks
        self.chaindb.save_block_as_unprocessed(block, computation_call_parent_dependency)


        #save the transactions to db
        vm = self.get_vm(timestamp = block.header.timestamp)
        vm.save_items_to_db_as_trie(block.transactions, block.header.transaction_root)
        vm.save_items_to_db_as_trie(block.receive_transactions, block.header.receive_transaction_root)

        #we don't want to persist because that will add it to the canonical chain.
        #We just want to save it to the database so we can process it later if needbe.
        self.chaindb.persist_non_canonical_block(block)
        #self.chaindb.persist_block(block)

        # If this was caused by a computation call requiring a parent chain, we save this block as a child of the dependency
        if computation_call_parent_dependency is not None:
            self.chaindb.add_block_child(computation_call_parent_dependency, block.header.hash)

        try:
            self.header = self.create_header_from_parent(self.get_canonical_head())
        except CanonicalHeadNotFound:
            self.header = self.get_vm_class_for_block_timestamp().create_genesis_block(self.wallet_address).header

        self.queue_block = None

        self.logger.debug(
            'SAVED_BLOCK_AS_UNPROCESSED: number %s | hash %s',
            block.number,
            encode_hex(block.hash),
        )
        return block

    def import_current_queue_block(self) -> BaseBlock:

        return self.import_block(self.queue_block)

    def import_current_queue_block_with_reward(self, node_staking_score_list: List[NodeStakingScore]) -> BaseBlock:
        reward_bundle = self.get_consensus_db().create_reward_bundle_for_block(self.wallet_address, node_staking_score_list, at_timestamp=Timestamp(int(time.time())))

        # #testing
        # reward_bundle = reward_bundle.copy(reward_type_2 = reward_bundle.reward_type_2.copy(amount=0))

        self.queue_block = self.queue_block.copy(reward_bundle = reward_bundle)

        return self.import_current_queue_block()

    def get_all_chronological_blocks_for_window(self, window_timestamp:Timestamp) -> List[BaseBlock]:
        validate_uint256(window_timestamp, title='timestamp')
        chronological_blocks = self.chain_head_db.load_chronological_block_window(window_timestamp)
        if chronological_blocks is None:
            return None
        else:
            list_of_blocks = []
            for chronological_block in chronological_blocks:
                block_hash = chronological_block[1]
                new_block = self.get_block_by_hash(block_hash)
                list_of_blocks.append(new_block)

            return list_of_blocks

    #
    # Chronologically consistent blockchain db API
    #
    def check_block_chronological_consistency(self, block: BaseBlock) -> List[Hash32]:
        '''
        Checks to see if the block breaks any chronological consistency. If it does, it will return a list of blocks that need to be reverted for this block to be imported

        returns list of block hashes that have to be reverted
        :param block:
        :return:
        '''

        consistency_keys = self.chaindb.get_block_chronological_consistency_keys(block.header.chain_address, block.header.block_number)
        block_hashes_to_revert = list()
        for consistency_key in consistency_keys:
            if consistency_key[0] > block.header.timestamp:
                block_hashes_to_revert.append(consistency_key[1])
        return block_hashes_to_revert

    #
    # Validation API
    #

    def get_allowed_time_of_next_block(self, chain_address: Address = None) -> Timestamp:
        if chain_address is None:
            chain_address = self.wallet_address

        try:
            canonical_head = self.chaindb.get_canonical_head(chain_address=chain_address)
        except CanonicalHeadNotFound:
            return Timestamp(0)
        vm = self.get_vm(timestamp=Timestamp(int(time.time())))
        min_allowed_time_between_blocks = vm.min_time_between_blocks
        return Timestamp(canonical_head.timestamp + min_allowed_time_between_blocks)



    def validate_block(self, block: BaseBlock) -> None:
        """
        Performs validation on a block that is either being mined or imported.

        Since block validation (specifically the uncle validation must have
        access to the ancestor blocks, this validation must occur at the Chain
        level.
        """

        self.validate_gaslimit(block.header)

    def validate_gaslimit(self, header: BlockHeader) -> None:
        """
        Validate the gas limit on the given header.
        """
        #parent_header = self.get_block_header_by_hash(header.parent_hash)
        #low_bound, high_bound = compute_gas_limit_bounds(parent_header)
        #if header.gas_limit < low_bound:
        #    raise ValidationError(
        #        "The gas limit on block {0} is too low: {1}. It must be at least {2}".format(
        #            encode_hex(header.hash), header.gas_limit, low_bound))
        if header.gas_limit > BLOCK_GAS_LIMIT:
            raise ValidationError(
                "The gas limit on block {0} is too high: {1}. It must be at most {2}".format(
                    encode_hex(header.hash), header.gas_limit, BLOCK_GAS_LIMIT))

    def validate_block_specification(self, block) -> bool:
        '''
        This validates everything we can without looking at the blockchain database. It doesnt need to assume
        that we have the block that sent the transactions.
        This that this can check:
            block signature
            send transaction signatures
            receive transaction signatures - dont need to check this. it doesnt add any security
            signatures of send transaction within receive transactions
            send transaction root matches transactions
            receive transaction root matches transactions

        '''

        if not isinstance(block, self.get_vm(timestamp = block.header.timestamp).get_block_class()):
            self.logger.debug("converting block to correct class")
            block = self.get_vm(timestamp = block.header.timestamp).convert_block_to_correct_class(block)

        block.header.check_signature_validity()

        for transaction in block.transactions:
            transaction.validate()

        for transaction in block.receive_transactions:
            transaction.validate()

        send_tx_root_hash, _ = make_trie_root_and_nodes(block.transactions)

        if block.header.transaction_root != send_tx_root_hash:
            raise ValidationError("Block has invalid transaction root")

        receive_tx_root_hash, _ = make_trie_root_and_nodes(block.receive_transactions)
        if block.header.receive_transaction_root != receive_tx_root_hash:
            raise ValidationError("Block has invalid receive transaction root")

        return True


    #
    # Stake API
    #

    def get_mature_stake(self, wallet_address: Address = None, raise_canonical_head_not_found_error:bool = False) -> int:
        if wallet_address is None:
            wallet_address = self.wallet_address
        coin_mature_time_for_staking = self.get_vm(timestamp = Timestamp(int(time.time()))).consensus_db.coin_mature_time_for_staking
        return self.chaindb.get_mature_stake(wallet_address, coin_mature_time_for_staking, raise_canonical_head_not_found_error = raise_canonical_head_not_found_error)

    # gets the stake for the timestamp corresponding to teh chronological block window, so it is all blocks for the next 1000 seconds.
    def get_mature_stake_for_chronological_block_window(self, chronological_block_window_timestamp: Timestamp, timestamp_for_stake: Timestamp = None):
        if timestamp_for_stake is not None and timestamp_for_stake < chronological_block_window_timestamp:
            raise ValidationError("Cannot get chronological block window stake for a timestamp before the window")

        if timestamp_for_stake is None:
            timestamp_for_stake = int(time.time())

        chronological_block_hash_timestamps = self.chain_head_db.load_chronological_block_window(chronological_block_window_timestamp)
        chronological_block_hashes = [x[1] for x in chronological_block_hash_timestamps]
        coin_mature_time_for_staking = self.get_vm(timestamp=timestamp_for_stake).consensus_db.coin_mature_time_for_staking
        return self.chaindb.get_total_block_stake_of_block_hashes(chronological_block_hashes, coin_mature_time_for_staking, timestamp_for_stake)



    def get_new_block_hash_to_test_peer_node_health(self) -> Hash32:
        '''
        returns one of the newest blocks we have seen.
        :return:
        '''
        before_this_timestamp = int(time.time()) - 60 # ask the peer for a block that was received at before 1 minute ago
        current_historical_window = int(time.time() / TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE

        for timestamp in range(current_historical_window,
                               current_historical_window-NUMBER_OF_HEAD_HASH_TO_SAVE*TIME_BETWEEN_HEAD_HASH_SAVE,
                               -1* TIME_BETWEEN_HEAD_HASH_SAVE):
            chronological_window = self.chain_head_db.load_chronological_block_window(timestamp)
            if chronological_window is not None:
                chronological_window.sort(key=lambda x: -1*x[0])
                for timestamp_hash in chronological_window:
                    if timestamp_hash[0] < before_this_timestamp:
                        return timestamp_hash[1]


        #if we get to here then we don't have any blocks within all chronological block windows...
        raise NoChronologicalBlocks()

    #
    # Min Block Gas API used for throttling the network
    #

    def re_initialize_historical_minimum_gas_price_at_genesis(self) -> None:
        '''
        re-initializes system with last set min gas price and net tpc cap
        '''
        hist_min_gas_price = self.min_gas_db.load_historical_minimum_gas_price()
        hist_tpc_cap = self.min_gas_db.load_historical_network_tpc_capability()

        if hist_min_gas_price is not None:
            init_min_gas_price = hist_min_gas_price[-1][1]
        else:
            init_min_gas_price = 1

        if hist_tpc_cap is not None:
            init_tpc_cap = hist_tpc_cap[-1][1]
        else:
            init_tpc_cap = self.get_local_tpc_cap()


        self.min_gas_db.initialize_historical_minimum_gas_price_at_genesis(init_min_gas_price, init_tpc_cap)



    def update_current_network_tpc_capability(self, current_network_tpc_cap: int, update_min_gas_price:bool = True) -> None:
        validate_uint256(current_network_tpc_cap, title="current_network_tpc_cap")
        self.min_gas_db.save_current_historical_network_tpc_capability(current_network_tpc_cap)

        if update_min_gas_price:
            self.update_PID_min_gas_price()


    #
    # new PID min gas system stuff
    #
    def update_PID_min_gas_price(self) -> None:
        #
        # This system requires transactions per 10 seconds, instead of transactions per 100 seconds
        #
        self.logger.debug("Updating min gas price using PID system")
        # Get the required parameters
        time_since_last_pid_update = self.min_gas_db.get_time_since_last_min_gas_price_PID_update()
        # def _calculate_next_min_gas_price_pid(self, historical_txpd: List[int], last_min_gas_price: int, wanted_txpd: int) -> int:
        tpd_tail = self.min_gas_db.get_tpd_tail()

        #We always take the newest historical min gas price as the last one calculated. It was calculated using the PID get_time_since_last_min_gas_price_PID_update() seconds ago.
        historical_min_gas_price = self.min_gas_db.load_historical_minimum_gas_price(return_int = False)
        if historical_min_gas_price is None:
            last_min_gas_price = 1
        else:
            last_min_gas_price = historical_min_gas_price[-1][1]

        historical_network_tpc_cap = self.min_gas_db.load_historical_network_tpc_capability()
        if historical_network_tpc_cap is None:
            self.logger.warning("Cannot update PID min gas price because we have no saved historical tx per centisecond network capability")
            return
        else:
            # we loaded transactions per 100 seconds, but want transactions per 10 seconds. so divide by 10
            network_tpd_cap = int(historical_network_tpc_cap[-1][1]/10)

        wanted_tpd = int(network_tpd_cap/3)
        if wanted_tpd < 1:
            wanted_tpd = 1

        new_min_gas_price = self.min_gas_db._calculate_next_min_gas_price_pid(tpd_tail, last_min_gas_price, wanted_tpd, time_since_last_pid_update)

        self.min_gas_db.append_historical_min_gas_price_now(new_min_gas_price)

        #after everything works, save this as the last time the pid updated
        self.min_gas_db.save_now_as_last_min_gas_price_PID_update()


    # def get_tpd_tail(self) -> List:
    #     #
    #     # Returns the transactions per 10 seconds for the past 20 seconds.
    #     #
    #     current_historical_window = int(time.time() / TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
    #
    #     tpd_tail = [0,0]
    #     now = int(time.time())
    #
    #     for historical_window_timestamp in range(current_historical_window,
    #                                              current_historical_window-2*TIME_BETWEEN_HEAD_HASH_SAVE,
    #                                              -TIME_BETWEEN_HEAD_HASH_SAVE):
    #         chronological_block_window = self.chain_head_db.load_chronological_block_window(historical_window_timestamp)
    #
    #
    #         if chronological_block_window is not None:
    #             for timestamp_block_hash in reversed(chronological_block_window):
    #                 #first count up the tx in the block
    #                 #if it is 0, then set to 1? in case block is all receive
    #                 num_tx_in_block = self.chaindb.get_number_of_total_tx_in_block(timestamp_block_hash[1])
    #                 if num_tx_in_block == 0:
    #                     num_tx_in_block = 1
    #
    #                 if (timestamp_block_hash[0] <= now) and (timestamp_block_hash[0] > now - 10):
    #                     tpd_tail[1] += num_tx_in_block
    #                 elif (timestamp_block_hash[0] <= now - 10) and (timestamp_block_hash[0] > now - 20):
    #                     tpd_tail[0] += num_tx_in_block
    #                 elif(timestamp_block_hash[0] <= now - 20):
    #                     return tpd_tail
    #
    #     return tpd_tail


    def update_tpc_from_chronological(self) -> None:
        # This updates the cached historical tpc from the actual historical blocks. If it finds that there is no difference
        # then it stops updating.
        self.logger.debug("Updating tpc from chronological")
        current_historical_window = int(time.time()/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
        current_centisecond = int(time.time()/100) * 100

        end_outer = current_historical_window-20*TIME_BETWEEN_HEAD_HASH_SAVE

        for historical_window_timestamp in range(current_historical_window,
                                                 end_outer,
                                                 -TIME_BETWEEN_HEAD_HASH_SAVE):

            tpc_sum_dict = {}
            chronological_block_window = self.chain_head_db.load_chronological_block_window(historical_window_timestamp)

            self.logger.debug('loading chronological block window for timestamp {}'.format(historical_window_timestamp))
            #zero the dictionary
            if historical_window_timestamp+TIME_BETWEEN_HEAD_HASH_SAVE < current_centisecond:
                end = historical_window_timestamp +TIME_BETWEEN_HEAD_HASH_SAVE
            else:
                end = current_centisecond+100

            for timestamp in range(historical_window_timestamp, end, 100):
                tpc_sum_dict[timestamp] = 0

            if chronological_block_window is not None:
                for timestamp_block_hash in chronological_block_window:
                    #first count up the tx in the block
                    #if it is 0, then set to 1? in case block is all receive
                    num_tx_in_block = self.chaindb.get_number_of_total_tx_in_block(timestamp_block_hash[1])
                    if num_tx_in_block == 0:
                        num_tx_in_block = 1

                    #then add them to the dict
                    centisecond_window_for_block = int(timestamp_block_hash[0]/100) * 100
                    if centisecond_window_for_block <= end:
                        tpc_sum_dict[centisecond_window_for_block] += num_tx_in_block

            same_as_database = self._update_tpc_from_chronological(tpc_sum_dict)

            if same_as_database == True:
                break


    def _update_tpc_from_chronological(self, new_hist_tpc_dict):
        '''
        returns True if they are all the same as what we already had in the database, otherwise it returns False
        '''
        if not isinstance(new_hist_tpc_dict, dict):
            raise ValidationError("Expected a dict. Didn't get a dict.")

        hist_tpc = self.chaindb.load_historical_tx_per_centisecond_from_chain()
        difference_found = False

        if hist_tpc is None:
            hist_tpc = list(new_hist_tpc_dict.items())
        else:
            hist_tpc_dict = dict(hist_tpc)
            for timestamp, tpc in new_hist_tpc_dict.items():

                if timestamp not in hist_tpc_dict or hist_tpc_dict[timestamp] != tpc:
                    #if tpc != 0:
                    difference_found = True
                hist_tpc_dict[timestamp] = tpc
            hist_tpc = list(hist_tpc_dict.items())

        #save it to db
        self.chaindb.save_historical_tx_per_centisecond_from_chain(hist_tpc, de_sparse = False)

        return not difference_found

    def get_local_tpc_cap(self) -> int:
        #base it on the time it takes to import a block

        from hvm.utils.profile import profile

        from hvm.db.backends.memory import MemoryDB
        from hvm import MainnetChain
        from hvm.chains.mainnet import (
            MAINNET_TPC_CAP_TEST_GENESIS_PARAMS,
            MAINNET_TPC_CAP_TEST_GENESIS_STATE,
            TPC_CAP_TEST_GENESIS_PRIVATE_KEY,
            MAINNET_TPC_CAP_TEST_BLOCK_TO_IMPORT,
        )
        from hvm.constants import random_private_keys

        db = MemoryDB()
        chain = MainnetChain.from_genesis(db,
                                          TPC_CAP_TEST_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(),
                                          MAINNET_TPC_CAP_TEST_GENESIS_PARAMS,
                                          MAINNET_TPC_CAP_TEST_GENESIS_STATE,
                                          private_key = TPC_CAP_TEST_GENESIS_PRIVATE_KEY)

        block_to_import = chain.get_vm(timestamp = MAINNET_TPC_CAP_TEST_BLOCK_TO_IMPORT['header']['timestamp']).get_block_class().from_dict(MAINNET_TPC_CAP_TEST_BLOCK_TO_IMPORT)

        chain.genesis_wallet_address = MAINNET_TPC_CAP_TEST_GENESIS_PARAMS['chain_address']
        chain.genesis_block_timestamp = MAINNET_TPC_CAP_TEST_GENESIS_PARAMS['timestamp']


        #@profile(sortby='cumulative')
        def temp():
            chain.import_block(block_to_import)
        start_time = time.time()
        temp()
        duration = time.time()-start_time
        #self.logger.debug('duration = {} seconds'.format(duration))
        tx_per_centisecond = int(100/duration)
        return tx_per_centisecond



    #
    # Consensus DB passthrough's that depend on block timestamp
    #

    def get_signed_peer_score(self, private_key: PrivateKey,
                              network_id: int,
                              peer_wallet_address: Address,
                              after_block_number: BlockNumber = None,
                              ) -> NodeStakingScore:
        # This function should always use the vm for the current timestamp. So we dont need to ask for timestamp
        return self.get_consensus_db(timestamp=Timestamp(int(time.time()))).get_signed_peer_score(private_key,
                                                       network_id,
                                                       peer_wallet_address,
                                                       after_block_number)

    def get_signed_peer_score_string_private_key(self,
                                                 private_key_string: bytes,
                                                 peer_wallet_address: Address,
                                                 after_block_number: BlockNumber = None,
                                                 ) -> NodeStakingScore:
        network_id = self.network_id
        # This always occurs at this time. So we take the current consensus db
        return self.get_consensus_db(timestamp=Timestamp(int(time.time()))).get_signed_peer_score_string_private_key(private_key_string,
                                                                          network_id,
                                                                          peer_wallet_address,
                                                                          after_block_number)

    def validate_node_staking_score(self,
                                    node_staking_score: NodeStakingScore,
                                    since_block_number: BlockNumber) -> None:
        # This depends on when the staking score was created. So get the consensus db given by that timestamp
        return self.get_consensus_db(timestamp = node_staking_score.timestamp).validate_node_staking_score(node_staking_score, since_block_number)


    def save_health_request(self, peer_wallet_address: Address, response_time_in_micros: int = float('inf')) -> None:
        # This always occurs at this time. So we take the current consensus db
        return self.get_consensus_db(timestamp=Timestamp(int(time.time()))).save_health_request(peer_wallet_address,
                                                           response_time_in_micros)

    def get_current_peer_node_health(self,peer_wallet_address: Address) -> PeerNodeHealth:
        return self.get_consensus_db(timestamp=Timestamp(int(time.time()))).get_current_peer_node_health(peer_wallet_address)


