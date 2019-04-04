from __future__ import absolute_import

from abc import (
    ABCMeta,
    abstractmethod
)
import rlp_cython as rlp
import time
import math
import operator
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
from hvm.db.chain import (
    BaseChainDB,
    ChainDB,
)
from hvm.db.journal import (
    JournalDB,
)
from hvm.constants import (
    BLOCK_GAS_LIMIT,
    BLANK_ROOT_HASH,
    NUMBER_OF_HEAD_HASH_TO_SAVE,
    TIME_BETWEEN_HEAD_HASH_SAVE,
    COIN_MATURE_TIME_FOR_STAKING,
    GENESIS_PARENT_HASH,
    MIN_GAS_PRICE_CALCULATION_AVERAGE_DELAY,
    MIN_GAS_PRICE_CALCULATION_AVERAGE_WINDOW_LENGTH,
    MIN_GAS_PRICE_CALCULATION_MIN_TIME_BETWEEN_CHANGE_IN_MIN_GAS_PRICE,
    MIN_TIME_BETWEEN_BLOCKS)

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

    RewardAmountRoundsToZero, TriedDeletingGenesisBlock, NoGenesisBlockPresent)
from eth_keys.exceptions import (
    BadSignature,
)
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
from hvm.rlp.consensus import NodeStakingScore

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


class BaseChain(Configurable, metaclass=ABCMeta):
    """
    The base class for all Chain objects
    """
    chaindb = None  # type: BaseChainDB
    chaindb_class = None  # type: Type[BaseChainDB]
    vm_configuration = None  # type: Tuple[Tuple[int, Type[BaseVM]], ...]
    genesis_wallet_address: Address = None
    genesis_block_timestamp: Timestamp = None

    #
    # Helpers
    #
    @classmethod
    @abstractmethod
    def get_chaindb_class(cls) -> Type[BaseChainDB]:
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
    def get_vm(self, header: BlockHeader=None) -> 'BaseVM':
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
    def get_blocks_on_chain_up_to_block_hash(self, chain_head_hash: Hash32) -> List[BaseBlock]:
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
    def import_current_queue_block_with_reward(self, node_staking_score_list: List[NodeStakingScore] = None) -> BaseBlock:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def purge_block_and_all_children_and_set_parent_as_chain_head_by_hash(self, block_hash_to_delete: Hash32) -> None:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def purge_block_and_all_children_and_set_parent_as_chain_head(self, existing_block_header: BlockHeader):
        raise NotImplementedError("Chain classes must implement this method")


    #
    # Transaction API
    #
    @abstractmethod
    def create_transaction(self, *args: Any, **kwargs: Any) -> BaseTransaction:
        raise NotImplementedError("Chain classes must implement this method")


    @abstractmethod
    def get_canonical_transaction(self, transaction_hash: Hash32) -> BaseTransaction:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def populate_queue_block_with_receive_tx(self) -> List[BaseReceiveTransaction]:
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
    # Execution API
    #
#    @abstractmethod
#    def apply_transaction(self, transaction):
#        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def estimate_gas(self, transaction: BaseTransaction, at_header: BlockHeader=None) -> int:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def import_block(self, block: BaseBlock, perform_validation: bool=True) -> BaseBlock:
        raise NotImplementedError("Chain classes must implement this method")


    @abstractmethod
    def import_chain(self, block_list: List[BaseBlock], perform_validation: bool=True, save_block_head_hash_timestamp: bool = True, allow_replacement: bool = True) -> None:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def import_chronological_block_window(self, block_list: List[BaseBlock], window_start_timestamp: Timestamp,
                                          save_block_head_hash_timestamp: bool = True,
                                          allow_unprocessed: bool = False) -> None:
        raise NotImplementedError("Chain classes must implement this method")



    #
    # Validation API
    #
    @abstractmethod
    def validate_block(self, block: BaseBlock) -> None:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def validate_gaslimit(self, header: BlockHeader) -> None:
        raise NotImplementedError("Chain classes must implement this method")

    #
    # Stake API
    #
    @abstractmethod
    def get_mature_stake(self) -> int:
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
    def get_local_tpc_cap(self) -> int:
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
    consensus_db_class = ConsensusDB

    chain_head_db: ChainHeadDB = None
    consensus_db: ConsensusDB = None
    chaindb: ChainDB = None
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
        self.consensus_db = self.get_consensus_db_class()(self.chaindb)

        try:
            self.header = self.create_header_from_parent(self.get_canonical_head())
        except CanonicalHeadNotFound:
            #this is a new block, lets make a genesis block
            self.logger.debug("Creating new genesis block on chain {}".format(self.wallet_address))
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

    #
    # Global Record and discard API
    #
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
    def get_chain_head_db_class(cls) -> Type[ChainHeadDB]:
        if cls.chain_head_db_class is None:
            raise AttributeError("`chain_head_db class` not set")
        return cls.chain_head_db_class

    @classmethod
    def get_consensus_db_class(cls) -> Type[ConsensusDB]:
        if cls.consensus_db_class is None:
            raise AttributeError("`consensus_db` not set")
        return cls.consensus_db_class

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

        genesis_vm_class = cls.get_vm_class_for_block_timestamp()

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
    def get_vm(self, header: BlockHeader=None) -> 'BaseVM':
        """
        Returns the VM instance for the given block number.
        """
        if header is None or header == self.header:
            header = self.header
            vm_class = self.get_vm_class_for_block_timestamp(header.timestamp)
            return vm_class(header=header,
                               chaindb=self.chaindb,
                               consensus_db = self.consensus_db,
                               wallet_address = self.wallet_address,
                               private_key=self.private_key,
                               network_id=self.network_id)
        else:
            vm_class = self.get_vm_class_for_block_timestamp(header.timestamp)

            return vm_class(header=header,
                            chaindb=self.chaindb,
                            consensus_db = self.consensus_db,
                            wallet_address = self.wallet_address,
                            private_key=self.private_key,
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

    def get_blocks_on_chain_up_to_block_hash(self, chain_head_hash: Hash32) -> List[BaseBlock]:
        chain_head_header = self.get_block_header_by_hash(chain_head_hash)
        to_block_number = chain_head_header.block_number
        chain_address = chain_head_header.chain_address

        return self.get_blocks_on_chain(0, to_block_number + 1, chain_address)


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
    # Blockchain Database API
    #
    def save_chain_head_hash_to_trie_for_time_period(self,block_header):
        timestamp = block_header.timestamp
        currently_saving_window = int(time.time()/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE +TIME_BETWEEN_HEAD_HASH_SAVE
        if timestamp <= currently_saving_window:
            #we have to go back and put it into the correct window, and update all windows after that
            #lets only keep the past NUMBER_OF_HEAD_HASH_TO_SAVE block_head_root_hash
            window_for_this_block = int(timestamp / TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE + TIME_BETWEEN_HEAD_HASH_SAVE
            #window_for_this_block = math.ceil((timestamp + 1)/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
#            if propogate_to_present:
            self.chain_head_db.add_block_hash_to_timestamp(block_header.chain_address, block_header.hash, window_for_this_block)
#            else:
#                self.chain_head_db.add_block_hash_to_timestamp_without_propogating_to_present(self.wallet_address, block_header.hash, window_for_this_block)




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
    def get_canonical_transaction(self, transaction_hash: Hash32) -> BaseTransaction:
        """
        Returns the requested transaction as specified by the transaction hash
        from the canonical chain.

        Raises TransactionNotFound if no transaction with the specified hash is
        found in the main chain.
        """
        (block_hash, index, is_receive) = self.chaindb.get_transaction_index(transaction_hash)

        block_header = self.get_block_header_by_hash(block_hash)

        VM = self.get_vm_class_for_block_timestamp(block_header.timestamp)

        if is_receive == False:
            transaction = self.chaindb.get_transaction_by_index_and_block_hash(
                block_hash,
                index,
                VM.get_transaction_class(),
            )
        else:
            transaction = self.chaindb.get_receive_transaction_by_index_and_block_hash(
                block_hash,
                index,
                VM.get_receive_transaction_class(),
            )

        if transaction.hash == transaction_hash:
            return transaction
        else:
            raise TransactionNotFound("Found transaction {} instead of {} in block {} at {}".format(
                encode_hex(transaction.hash),
                encode_hex(transaction_hash),
                block_hash,
                index,
            ))

    def create_transaction(self, *args: Any, **kwargs: Any) -> BaseTransaction:
        """
        Passthrough helper to the current VM class.
        """
        return self.get_vm().create_transaction(*args, **kwargs)

    def create_and_sign_transaction(self, *args: Any, **kwargs: Any) -> BaseTransaction:
        transaction = self.create_transaction(*args, **kwargs)
        signed_transaction = transaction.get_signed(self.private_key, self.network_id)
        return signed_transaction

    def create_and_sign_transaction_for_queue_block(self, *args: Any, **kwargs: Any) -> BaseTransaction:
        tx_nonce = self.get_current_queue_block_nonce()

        transaction = self.create_and_sign_transaction(nonce = tx_nonce, *args, **kwargs)

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
            return False, False
        transactions = []
        for tx_key in tx_keys:
            tx = self.get_canonical_transaction(tx_key.transaction_hash)
            transactions.append(tx)
        return transactions, tx_keys

    def create_receivable_transactions(self) -> List[BaseReceiveTransaction]:
        tx_keys = self.get_vm().state.account_db.get_receivable_transactions(self.wallet_address)
        if len(tx_keys) == 0:
            return []

        receive_transactions = []
        for tx_key in tx_keys:
            #find out if it is a receive or a refund
            block_hash, index, is_receive = self.chaindb.get_transaction_index(tx_key.transaction_hash)

            re_tx = self.get_vm().create_receive_transaction(
                    sender_block_hash = tx_key.sender_block_hash,
                    send_transaction_hash=tx_key.transaction_hash,
                    is_refund=is_receive,
                    )

            receive_transactions.append(re_tx)
        return receive_transactions

    def populate_queue_block_with_receive_tx(self) -> List[BaseReceiveTransaction]:
        receive_tx = self.create_receivable_transactions()
        self.add_transactions_to_queue_block(receive_tx)
        return receive_tx

    # def get_receive_transactions(self, wallet_address: Address):
    #     validate_canonical_address(wallet_address, title="wallet_address")
    #     vm = self.get_vm()
    #     account_db = vm.state.account_db
    #     receivable_tx_keys = account_db.get_receivable_transactions(wallet_address)
    #     #todo: finish this function
    #     #print(receivable_tx_hashes)


    #
    # Execution API
    #

    def estimate_gas(self, transaction: BaseTransaction, at_header: BlockHeader=None) -> int:
        """
        Returns an estimation of the amount of gas the given transaction will
        use if executed on top of the block specified by the given header.
        """
        if at_header is None:
            at_header = self.get_canonical_head()
        with self.get_vm(at_header).state_in_temp_block() as state:
            return self.gas_estimator(state, transaction)




    def validate_time_between_blocks(self,block):
        if not block.is_genesis:
            #first make sure enough time has passed since genesis. We need at least TIME_BETWEEN_HEAD_HASH_SAVE since genesis so that the
            # genesis historical root hash only contains the genesis chain.
            if block.header.timestamp < (self.genesis_block_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE):
                raise NotEnoughTimeBetweenBlocks("Not enough time has passed since the genesis block. Must wait at least {} seconds after genesis block. "
                                                 "This block timestamp is {}, genesis block timestamp is {}.".format(TIME_BETWEEN_HEAD_HASH_SAVE, block.header.timestamp, self.genesis_block_timestamp))

            parent_header = self.chaindb.get_block_header_by_hash(block.header.parent_hash)
            parent_block_timestamp = parent_header.timestamp
            if (block.header.timestamp - parent_block_timestamp) < MIN_TIME_BETWEEN_BLOCKS:
                raise NotEnoughTimeBetweenBlocks("Not enough time between blocks. We require {} seconds between blocks. The block timestamp is {}, and the previous block timestamp is {}".format(
                    MIN_TIME_BETWEEN_BLOCKS, block.header.timestamp, parent_block_timestamp
                ))
        return

    #
    # Reverting block functions
    #

    def delete_canonical_chain(self, wallet_address: Address, vm: 'BaseVM', save_block_head_hash_timestamp:bool = True) -> None:
        self.logger.debug("delete_canonical_chain. Chain address {}".format(encode_hex(wallet_address)))
        self.chain_head_db.delete_chain(wallet_address, save_block_head_hash_timestamp)
        self.chaindb.delete_canonical_chain(wallet_address)
        vm.state.clear_account_keep_receivable_transactions_and_persist(wallet_address)

    def set_parent_as_canonical_head(self, existing_block_header: BlockHeader, vm: 'BaseVM', save_block_head_hash_timestamp:bool = True) -> None:
        block_parent_header = self.chaindb.get_block_header_by_hash(existing_block_header.parent_hash)
        self.logger.debug("Setting new block as canonical head after reverting blocks. Chain address {}, header hash {}".format(encode_hex(existing_block_header.chain_address), encode_hex(block_parent_header.hash)))

        if save_block_head_hash_timestamp:
            self.save_chain_head_hash_to_trie_for_time_period(block_parent_header)

        self.chain_head_db.set_chain_head_hash(block_parent_header.chain_address, block_parent_header.hash)
        self.chaindb._set_as_canonical_chain_head(block_parent_header)
        vm.state.revert_account_to_hash_keep_receivable_transactions_and_persist(block_parent_header.account_hash, block_parent_header.chain_address)

    def revert_block(self, descendant_block_hash: Hash32, vm: 'BaseVM') -> None:
        self.logger.debug('Reverting block with hash {}'.format(encode_hex(descendant_block_hash)))
        descendant_block_header = self.chaindb.get_block_header_by_hash(descendant_block_hash)
        self.chain_head_db.delete_block_hash_from_chronological_window(descendant_block_hash, descendant_block_header.timestamp)
        self.chaindb.remove_block_from_all_parent_child_lookups(descendant_block_header, vm.get_block_class().receive_transaction_class)
        self.chaindb.delete_all_block_children_lookups(descendant_block_hash)

        #for every one, re-add pending receive transaction for all receive transactions only if sending block still exists
        #make all blocks unprocessed so that receivable transactions are not saved that came from one of the non-canonical blocks.
        vm.reverse_pending_transactions(descendant_block_header)

        # remove the block from the canonical chain. This must be done last because reversing the pending transactions requires that it
        # is still in the canonical chain to look up transactions
        self.chaindb.delete_block_from_canonical_chain(descendant_block_hash)
        #self.chaindb.save_unprocessed_block_lookup(descendant_block_hash)

    def purge_block_and_all_children_and_set_parent_as_chain_head_by_hash(self, block_hash_to_delete: Hash32, save_block_head_hash_timestamp: bool = True) -> None:

        genesis_block_hash = self.chaindb.get_canonical_block_hash(BlockNumber(0), self.genesis_wallet_address)
        if block_hash_to_delete == genesis_block_hash:
            raise TriedDeletingGenesisBlock("Attempted to delete genesis block. This is not allowed.")

        block_header_to_delete = self.chaindb.get_block_header_by_hash(block_hash_to_delete)
        self.purge_block_and_all_children_and_set_parent_as_chain_head(block_header_to_delete, save_block_head_hash_timestamp)


    def purge_block_and_all_children_and_set_parent_as_chain_head(self, existing_block_header: BlockHeader, save_block_head_hash_timestamp: bool = True) -> None:
        # First make sure it is actually in the canonical chain. If not, then we don't have anything to do.
        if self.chaindb.is_in_canonical_chain(existing_block_header.hash):

            vm = self.get_vm()
            if existing_block_header.block_number == 0:
                self.delete_canonical_chain(existing_block_header.chain_address, vm, save_block_head_hash_timestamp)
            else:
                #set the parent block as the new canonical head, and handle all the data for that
                self.set_parent_as_canonical_head(existing_block_header, vm, save_block_head_hash_timestamp)

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
                                    self.delete_canonical_chain(descendant_block_header.chain_address, vm, save_block_head_hash_timestamp)
                                else:
                                    self.set_parent_as_canonical_head(descendant_block_header, vm, save_block_head_hash_timestamp)

                #now we know what the new heads are, so we can deal with the rest of the descendants
                for descendant_block_hash in all_descendant_block_hashes:
                    #here, since we are already going through all children, we don't need this function to purge children as well
                    if self.chaindb.is_block_unprocessed(descendant_block_hash):
                        self.purge_unprocessed_block(descendant_block_hash, purge_children_too = False)
                    else:
                        self.revert_block(descendant_block_hash, vm)

            self.revert_block(existing_block_header.hash, vm)

            #persist changes
            vm.state.account_db.persist()
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




    def import_chronological_block_window(self, block_list: List[BaseBlock], window_start_timestamp: Timestamp, save_block_head_hash_timestamp:bool = True, allow_unprocessed:bool =False) -> None:
        validate_uint256(window_start_timestamp, title='timestamp')

        if block_list is None or len(block_list) == 0:
            return

        #if we are given a block that is not one of the two allowed classes, try converting it.
        if len(block_list) > 0 and not isinstance(block_list[0], self.get_vm().get_block_class()):
            self.logger.debug("converting chain to correct class")
            corrected_block_list = []
            for block in block_list:
                corrected_block = self.get_vm().convert_block_to_correct_class(block)
                corrected_block_list.append(corrected_block)
            block_list = corrected_block_list


        #first we delete any blocks we have in the same window that are not in the new block list
        local_chronological_timestamp_block_window = self.chain_head_db.load_chronological_block_window(window_start_timestamp)

        if local_chronological_timestamp_block_window is not None:
            local_block_hash_list = [x[1] for x in local_chronological_timestamp_block_window]

            new_block_hash_list = [block.hash for block in block_list]

            block_hashes_to_delete = effecient_diff(new_block_hash_list, local_block_hash_list)
            if len(block_hashes_to_delete) > 0:
                self.logger.debug("deleting existing blocks in chronological window {}".format(block_hashes_to_delete))

            for block_hash_to_delete in block_hashes_to_delete:
                self.purge_block_and_all_children_and_set_parent_as_chain_head_by_hash(block_hash_to_delete)

        if len(block_list) > 0:
            self.logger.debug("starting block import for chronological block window")
            #if block list is empty, load the local historical root hashes and delete them all
            for block in block_list:
                wallet_address = block.header.chain_address
                self.import_block(block, wallet_address = wallet_address, save_block_head_hash_timestamp = save_block_head_hash_timestamp, allow_unprocessed=allow_unprocessed)
        else:
            self.logger.debug("importing an empty chronological window. going to make sure we have a saved historical root hash")
            historical_root_hashes = self.chain_head_db.get_historical_root_hashes()
            if historical_root_hashes is not None:
                #historical_root_hashes_dict = dict(historical_root_hashes)
                #if it does exist, make sure it is the same as the last one. if not, then delete all newer
                try:
                    self.chain_head_db.propogate_previous_historical_root_hash_to_timestamp(window_start_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE)
                except AppendHistoricalRootHashTooOld:
                    self.logger.debug("Tried to propogate the previous historical root hash but there was none. This shouldn't happen")
        #self.logger.debug("historical root hashes after chronological block import {}".format(self.chain_head_db.get_historical_root_hashes()))

    def import_chain(self, block_list: List[BaseBlock], perform_validation: bool=True, save_block_head_hash_timestamp: bool = True, allow_replacement: bool = True) -> None:
        self.logger.debug("importing chain")
        #if we are given a block that is not one of the two allowed classes, try converting it.
        if len(block_list) > 0 and not isinstance(block_list[0], self.get_vm().get_block_class()):
            self.logger.debug("converting chain to correct class")
            corrected_block_list = []
            for block in block_list:
                corrected_block = self.get_vm().convert_block_to_correct_class(block)
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
                     ensure_block_unchanged:bool = True) -> BaseBlock:

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

        journal_enabled = False

        #if we are given a block that is not one of the two allowed classes, try converting it.
        #There is no reason why this should be a queueblock, because a queueblock would never come over the network, it
        #it always generated locally, and should have the correct class.
        if not isinstance(block, self.get_vm().get_block_class()):
            self.logger.debug("converting block to correct class")
            block = self.get_vm().convert_block_to_correct_class(block)

        if not isinstance(block, self.get_vm().get_queue_block_class()) and block.header.chain_address == self.genesis_wallet_address and block.header.block_number == 0:
            try:
                our_genesis_hash = self.chaindb.get_canonical_block_header_by_number(BlockNumber(0), self.genesis_wallet_address).hash
            except HeaderNotFound:
                raise NoGenesisBlockPresent("Tried importing a block, but we have no genesis block loaded. Need to load a genesis block first.")

            if block.header.hash == our_genesis_hash:
                return block
            else:
                raise ValidationError("Tried to import a new genesis block on the genesis chain. This is not allowed.")


        if len(block.transactions) == 0 and len(block.receive_transactions) == 0:
            # if block.reward_bundle is None:
            #     raise ValidationError('The block must have at least 1 transaction, or a non-zero reward bundle. Reward bundle = None')
            if (block.reward_bundle.reward_type_1.amount == 0 and block.reward_bundle.reward_type_2.amount == 0):
                raise RewardAmountRoundsToZero('The reward bundle has amount = 0 for all types of rewards. This usually means more time needs to pass before creating reward bundle.')

        #if we are adding to the top of the chain, or beyond, we need to check for unprocessed blocks
        #handle deleting any unprocessed blocks that will be replaced.
        if block.number >= self.header.block_number:

            existing_unprocessed_block_hash = self.chaindb.get_unprocessed_block_hash_by_block_number(self.wallet_address, block.number)

            if (existing_unprocessed_block_hash != block.hash) and (existing_unprocessed_block_hash is not None):
                if not allow_replacement:
                    raise ReplacingBlocksNotAllowed()

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
                raise ReplacingBlocksNotAllowed()


            self.logger.debug("went into block replacing mode")
            self.logger.debug("block.number = {}, self.header.block_number = {}".format(block.number,self.header.block_number))
            self.logger.debug("this chains wallet address = {}, this block's sender = {}".format(encode_hex(self.wallet_address), encode_hex(block.sender)))


            #check to see if we can load the existing canonical block
            existing_block_header = self.chaindb.get_canonical_block_header_by_number(block.number, self.wallet_address)

            if existing_block_header.hash == block.header.hash:
                self.logger.debug("tried to import a block that has a hash that matches the local block. no import required.")
                return block
            else:

                self.enable_journal_db()
                journal_record = self.record_journal()
                journal_enabled = True

                self.purge_block_and_all_children_and_set_parent_as_chain_head(existing_block_header)



        try:
            return_block = self._import_block(block = block,
                                              perform_validation = perform_validation,
                                              save_block_head_hash_timestamp = save_block_head_hash_timestamp,
                                              allow_unprocessed = allow_unprocessed,
                                              ensure_block_unchanged= ensure_block_unchanged)

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
                      ensure_block_unchanged: bool = True) -> BaseBlock:
        """
        Imports a complete block.
        """

        self.logger.debug("importing block number {}".format(block.number))

        self.validate_time_between_blocks(block)

        if isinstance(block, self.get_vm().get_queue_block_class()):
            # If it was a queueblock, then the header will have changed after importing
            perform_validation = False
            ensure_block_unchanged = False


        if not self.chaindb.is_block_unprocessed(block.header.parent_hash):

            #this part checks to make sure the parent exists
            try:
                vm = self.get_vm()
                imported_block = vm.import_block(block)


                # Validate the imported block.
                if ensure_block_unchanged:
                    self.logger.debug('ensuring block unchanged')
                    ensure_imported_block_unchanged(imported_block, block)
                else:
                    self.logger.debug('Not checking block for changes.')
                if perform_validation:
                    self.validate_block(imported_block)


                #self.chain_head_db.set_chain_head_hash(self.wallet_address, imported_block.header.hash)

                if save_block_head_hash_timestamp:
                    self.chain_head_db.add_block_hash_to_chronological_window(imported_block.header.hash, imported_block.header.timestamp)
                    self.save_chain_head_hash_to_trie_for_time_period(imported_block.header)

                self.chain_head_db.set_chain_head_hash(imported_block.header.chain_address, imported_block.header.hash)
                self.chain_head_db.persist(True)
                self.chaindb.persist_block(imported_block)
                vm.state.account_db.persist(save_account_hash = True, wallet_address = self.wallet_address)


                #here we must delete the unprocessed lookup before importing children
                #because the children cannot be imported if their chain parent is unprocessed.
                #but we cannot delete the lookup for unprocessed children yet.
                self.chaindb.remove_block_from_unprocessed(imported_block)

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

                self.import_unprocessed_children(imported_block,
                                                 perform_validation= True,
                                               save_block_head_hash_timestamp = save_block_head_hash_timestamp,
                                               allow_unprocessed = True)


                #finally, remove unprocessed database lookups for this block
                self.chaindb.delete_unprocessed_children_blocks_lookup(imported_block.hash)

                return_block = imported_block


            except ReceivableTransactionNotFound as e:
                if not allow_unprocessed:
                    raise UnprocessedBlockNotAllowed()
                self.logger.debug("Saving block as unprocessed because of ReceivableTransactionNotFound error: {}".format(e))
                return_block = self.save_block_as_unprocessed(block)
                if self.raise_errors:
                    raise e


            except RewardProofSenderBlockMissing as e:
                if not allow_unprocessed:
                    raise UnprocessedBlockNotAllowed()
                self.logger.debug("Saving block as unprocessed because of RewardProofSenderBlockMissing error: {}".format(e))
                return_block = self.save_block_as_unprocessed(block)

        else:
            if not allow_unprocessed:
                raise UnprocessedBlockNotAllowed()
            self.logger.debug("Saving block as unprocessed because parent on this chain is unprocessed")
            return_block = self.save_block_as_unprocessed(block)


        return return_block



    def import_unprocessed_children(self, block, *args, **kwargs):
        """
        Checks all block children for unprocessed blocks that were waiting for this one to be processed.
        This includes children via transactions, and the children on this chain.
        If it finds any unprocessed blocks it will, along with import_block, recursively import all unprocessed children.
        it ignores errors so that it can make it through all of the children without stopping
        """
        if self.chaindb.has_unprocessed_children(block.hash):
            self.logger.debug("HAS UNPROCESSED BLOCKS")
            #try to import all children
            children_block_hashes = self.chaindb.get_block_children(block.hash)
            if children_block_hashes != None:
                self.logger.debug("children_block_hashes = {}".format([encode_hex(x) for x in children_block_hashes]))
                for child_block_hash in children_block_hashes:
                    #this includes the child in this actual chain as well as children from send transactions.
                    if self.chaindb.is_block_unprocessed(child_block_hash):
                        self.logger.debug("importing child block")
                        #we want to catch errors here so that we process all children blocks. If one block has an error it will just go to the next
                        try:
                            #attempt to import.
                            #get chain for wallet address
                            #child_chain = Chain(self.base_db, child_wallet_address)
                            #get block
                            child_block = self.get_block_by_hash(child_block_hash)
                            if child_block.header.chain_address != self.wallet_address:
                                self.logger.debug("Changing to chain with wallet address {}".format(encode_hex(child_block.header.chain_address)))
                                self.set_new_wallet_address(wallet_address=child_block.header.chain_address)
                            self._import_block(child_block, *args, **kwargs)
                        except Exception as e:
                            self.logger.error("Tried to import an unprocessed child block and got this error {}".format(e))
                            #todo need to delete child block and all of its children
                            raise e
                            #pass


    def save_block_as_unprocessed(self, block):
        #if it is already saved as unprocesessed, do nothing
        if self.chaindb.is_block_unprocessed(block.hash):
            return block

        #before adding to unprocessed blocks, make sure the receive transactions are valid
        # for receive_transaction in block.receive_transactions:
        #     #there must be at least 1 to get this far
        #     receive_transaction.validate()

        #now we add it to unprocessed blocks
        self.chaindb.save_block_as_unprocessed(block)


        #save the transactions to db
        vm = self.get_vm()
        vm.save_items_to_db_as_trie(block.transactions, block.header.transaction_root)
        vm.save_items_to_db_as_trie(block.receive_transactions, block.header.receive_transaction_root)

        #we don't want to persist because that will add it to the canonical chain.
        #We just want to save it to the database so we can process it later if needbe.
        self.chaindb.persist_non_canonical_block(block)
        #self.chaindb.persist_block(block)

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

    def import_current_queue_block_with_reward(self, node_staking_score_list: List[NodeStakingScore] = None) -> BaseBlock:
        reward_bundle = self.consensus_db.create_reward_bundle_for_block(self.wallet_address, node_staking_score_list, at_timestamp=Timestamp(int(time.time())))

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
    # Validation API
    #
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

    def validate_block_specification(self, block):
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

        if not isinstance(block, self.get_vm().get_block_class()):
            self.logger.debug("converting block to correct class")
            block = self.get_vm().convert_block_to_correct_class(block)

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

    def get_mature_stake(self) -> int:
        return self.chaindb.get_mature_stake(self.wallet_address)

    # gets the stake for the timestamp corresponding to teh chronological block window, so it is all blocks for the next 1000 seconds.
    def get_mature_stake_for_chronological_block_window(self, chronological_block_window_timestamp: Timestamp, timestamp_for_stake: Timestamp = None):
        if timestamp_for_stake is not None and timestamp_for_stake < chronological_block_window_timestamp:
            raise ValidationError("Cannot get chronological block window stake for a timestamp before the window")

        chronological_block_hash_timestamps = self.chain_head_db.load_chronological_block_window(chronological_block_window_timestamp)
        chronological_block_hashes = [x[1] for x in chronological_block_hash_timestamps]
        return self.chaindb.get_total_block_stake_of_block_hashes(chronological_block_hashes, timestamp_for_stake)



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
        hist_min_gas_price = self.chaindb.load_historical_minimum_gas_price()
        hist_tpc_cap = self.chaindb.load_historical_network_tpc_capability()
        hist_tx_per_centisecond = self.chaindb.load_historical_tx_per_centisecond()

        if hist_min_gas_price is not None:
            init_min_gas_price = hist_min_gas_price[-1][1]
        else:
            init_min_gas_price = 1

        if hist_tpc_cap is not None:
            init_tpc_cap = hist_tpc_cap[-1][1]
        else:
            init_tpc_cap = self.get_local_tpc_cap()

        if hist_tx_per_centisecond is not None:
            init_tpc = hist_tx_per_centisecond[-1][1]
        else:
            init_tpc = None

        self.chaindb.initialize_historical_minimum_gas_price_at_genesis(init_min_gas_price, init_tpc_cap, init_tpc)

    def update_current_network_tpc_capability(self, current_network_tpc_cap: int, update_min_gas_price:bool = True) -> None:
        validate_uint256(current_network_tpc_cap, title="current_network_tpc_cap")
        self.chaindb.save_current_historical_network_tpc_capability(current_network_tpc_cap)

        if update_min_gas_price:
            current_centisecond = int(time.time()/100) * 100
            timestamp_min_gas_price_updated = self.update_tpc_from_chronological(update_min_gas_price = True)

            if timestamp_min_gas_price_updated > current_centisecond:
                self.chaindb._recalculate_historical_mimimum_gas_price(current_centisecond)




    def update_tpc_from_chronological(self, update_min_gas_price: bool = True):
        #start at the newest window, if the same tps stop. but if different tps keep going back
        self.logger.debug("Updating tpc from chronological")
        current_historical_window = int(time.time()/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
        current_centisecond = int(time.time()/100) * 100

        #load this once to find out if its None. If it is None, then the node just started, lets only go back 50 steps
        #hist_tpc = self.chaindb.load_historical_tx_per_centisecond()


        end_outer = current_historical_window-6*TIME_BETWEEN_HEAD_HASH_SAVE


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
                    num_tx_in_block = self.chaindb.get_number_of_send_tx_in_block(timestamp_block_hash[1])
                    #then add them to the dict
                    centisecond_window_for_block = int(timestamp_block_hash[0]/100) * 100
                    if centisecond_window_for_block <= end:
                        tpc_sum_dict[centisecond_window_for_block] += num_tx_in_block

            same_as_database = self._update_tpc_from_chronological(tpc_sum_dict)

            if same_as_database == True:
                break

        if update_min_gas_price:
            self.chaindb._recalculate_historical_mimimum_gas_price(historical_window_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE)

        return historical_window_timestamp+TIME_BETWEEN_HEAD_HASH_SAVE


    def _update_tpc_from_chronological(self, new_hist_tpc_dict):
        '''
        returns True if they are all the same as what we already had in the database, otherwise it returns False
        '''
        if not isinstance(new_hist_tpc_dict, dict):
            raise ValidationError("Expected a dict. Didn't get a dict.")

        hist_tpc = self.chaindb.load_historical_tx_per_centisecond()
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

        #print(hist_tpc)
        #save it to db
        self.chaindb.save_historical_tx_per_centisecond(hist_tpc, de_sparse = False)

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

        block_to_import = chain.get_vm().get_block_class().from_dict(MAINNET_TPC_CAP_TEST_BLOCK_TO_IMPORT)


        #@profile(sortby='cumulative')
        def temp():
            chain.import_block(block_to_import)
        start_time = time.time()
        temp()
        duration = time.time()-start_time
        #self.logger.debug('duration = {} seconds'.format(duration))
        tx_per_centisecond = int(100/duration)
        return tx_per_centisecond





# This was moved to helios
# This class is a work in progress; its main purpose is to define the API of an asyncio-compatible
# Chain implementation.
# class AsyncChain(Chain):
#
#     async def coro_import_block(self,
#                                 block: BlockHeader,
#                                 perform_validation: bool=True) -> BaseBlock:
#         raise NotImplementedError()
#
#     async def coro_import_chain(self, block_list: List[BaseBlock], perform_validation: bool=True, save_block_head_hash_timestamp: bool = True, allow_replacement: bool = True) -> None:
#         raise NotImplementedError()
#
#
#     async def coro_get_all_chronological_blocks_for_window(self, window_timestamp: Timestamp) -> List[BaseBlock]:
#         raise NotImplementedError()
#
#     async def coro_import_chronological_block_window(self, block_list: List[BaseBlock], window_start_timestamp: Timestamp,
#                                           save_block_head_hash_timestamp: bool = True,
#                                           allow_unprocessed: bool = False) -> None:
#         raise NotImplementedError()
#
#     async def coro_update_current_network_tpc_capability(self, current_network_tpc_cap: int,
#                                               update_min_gas_price: bool = True) -> None:
#         raise NotImplementedError()
#
#     async def coro_get_local_tpc_cap(self) -> int:
#         raise NotImplementedError()
#
#     async def coro_re_initialize_historical_minimum_gas_price_at_genesis(self) -> None:
#         raise NotImplementedError()
#
#     async def coro_import_current_queue_block_with_reward(self, node_staking_score_list: List[NodeStakingScore] = None) -> BaseBlock:
#         raise NotImplementedError()
#
#     async def coro_get_block_by_hash(self, block_hash: Hash32) -> BaseBlock:
#         raise NotImplementedError("Chain classes must implement this method")
#
#     async def coro_get_block_by_header(self, block_header: BlockHeader) -> BaseBlock:
#         raise NotImplementedError("Chain classes must implement this method")
#
#     async def coro_get_block_by_number(self, block_number: BlockNumber, chain_address: Address = None) -> BaseBlock:
#         raise NotImplementedError("Chain classes must implement this method")
#
#     async def coro_get_blocks_on_chain(self, start: int, end: int, chain_address: Address = None) -> List[BaseBlock]:
#         raise NotImplementedError("Chain classes must implement this method")
#
#     async def coro_get_all_blocks_on_chain(self, chain_address: Address = None) -> List[BaseBlock]:
#         raise NotImplementedError("Chain classes must implement this method")
#
#     async def coro_get_all_blocks_on_chain_by_head_block_hash(self, chain_head_hash: Hash32) -> List[BaseBlock]:
#         raise NotImplementedError("Chain classes must implement this method")
#
#     async def coro_get_blocks_on_chain_up_to_block_hash(self, chain_head_hash: Hash32) -> List[BaseBlock]:
#         raise NotImplementedError("Chain classes must implement this method")

    #
    # Async chain functions for calling chain directly
    #


    # async def coro_import_chain(self, *args, **kwargs):
    #     loop = asyncio.get_event_loop()
    #
    #     return await loop.run_in_executor(
    #         None,
    #         partial(self.import_chain, *args, **kwargs)
    #     )


    # async def coro_import_current_queue_block_with_reward(self, *args, **kwargs):
    #     loop = asyncio.get_event_loop()
    #
    #     return await loop.run_in_executor(
    #         None,
    #         partial(self.import_current_queue_block_with_reward, *args, **kwargs)
    #     )

    # async def coro_get_block_by_hash(self, *args, **kwargs):
    #     loop = asyncio.get_event_loop()
    #
    #     return await loop.run_in_executor(
    #         None,
    #         partial(self.get_block_by_hash, *args, **kwargs)
    #     )

    # async def coro_get_blocks_on_chain(self, *args, **kwargs):
    #     loop = asyncio.get_event_loop()
    #
    #     return await loop.run_in_executor(
    #         None,
    #         partial(self.get_blocks_on_chain, *args, **kwargs)
    #     )

    # async def coro_get_blocks_on_chain_up_to_block_hash(self, *args, **kwargs):
    #     loop = asyncio.get_event_loop()
    #
    #     return await loop.run_in_executor(
    #         None,
    #         partial(self.get_blocks_on_chain_up_to_block_hash, *args, **kwargs)
    #     )


    # async def coro_get_block_by_number(self, *args, **kwargs):
    #     loop = asyncio.get_event_loop()
    #
    #     return await loop.run_in_executor(
    #         None,
    #         partial(self.get_block_by_number, *args, **kwargs)
    #     )

    # async def coro_import_current_queue_block(self, *args, **kwargs):
    #     loop = asyncio.get_event_loop()
    #
    #     return await loop.run_in_executor(
    #         None,
    #         partial(self.import_current_queue_block, *args, **kwargs)
    #     )

    # async def coro_purge_block_and_all_children_and_set_parent_as_chain_head_by_hash(self, *args, **kwargs):
    #     loop = asyncio.get_event_loop()
    #
    #     return await loop.run_in_executor(
    #         None,
    #         partial(self.purge_block_and_all_children_and_set_parent_as_chain_head_by_hash, *args, **kwargs)
    #     )



