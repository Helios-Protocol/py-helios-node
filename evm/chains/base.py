from __future__ import absolute_import

from abc import (
    ABCMeta,
    abstractmethod
)
import rlp
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
)

import logging

from cytoolz import (
    assoc,
    groupby,
)

from eth_typing import (
    Address,
    BlockNumber,
    Hash32,
)

from eth_utils import (
    to_tuple,
    to_set,
)


from evm.db.backends.base import BaseDB
from evm.db.chain import (
    BaseChainDB,
    ChainDB,
)
from evm.db.journal import (
    JournalDB,
)
from evm.constants import (
    BLOCK_GAS_LIMIT,
    BLANK_ROOT_HASH,
    NUMBER_OF_HEAD_HASH_TO_SAVE,
    TIME_BETWEEN_HEAD_HASH_SAVE,
    COIN_MATURE_TIME_FOR_STAKING,
    GENESIS_PARENT_HASH,
    MIN_GAS_PRICE_CALCULATION_AVERAGE_DELAY,
    MIN_GAS_PRICE_CALCULATION_AVERAGE_WINDOW_LENGTH,
    MIN_GAS_PRICE_CALCULATION_MIN_TIME_BETWEEN_CHANGE_IN_MIN_GAS_PRICE,
    MAX_NUM_HISTORICAL_MIN_GAS_PRICE_TO_KEEP,
)


from evm import constants
from evm.estimators import (
    get_gas_estimator,
)
from evm.exceptions import (
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
)
from eth_keys.exceptions import (
    BadSignature,
)
from evm.validation import (
    validate_block_number,
    validate_uint256,
    validate_word,
    validate_vm_configuration,
    validate_canonical_address,
    validate_is_queue_block,
    validate_centisecond_timestamp,
)
from evm.rlp.blocks import (
    BaseBlock,
    BaseQueueBlock,
)
from evm.rlp.headers import (
    BlockHeader,
    HeaderParams,
)
from evm.rlp.transactions import (
    BaseTransaction,
    BaseReceiveTransaction
)
from evm.utils.db import (
    apply_state_dict,
)
from evm.utils.datatypes import (
    Configurable,
)
from evm.utils.headers import (
    compute_gas_limit_bounds,
)
from evm.utils.hexadecimal import (
    encode_hex,
    decode_hex
)
from evm.utils.rlp import (
    ensure_imported_block_unchanged,
)

from evm.db.chain_head import ChainHeadDB

from eth_keys import keys
from eth_keys.datatypes import(
        BaseKey,
        PublicKey,
        PrivateKey
)

from evm.utils.numeric import (
    effecient_diff, 
    are_items_in_list_equal,
)

from sortedcontainers import (
    SortedList,
    SortedDict,      
)

if TYPE_CHECKING:
    from evm.vm.base import BaseVM  # noqa: F401


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
    def get_ancestors(self, limit: int, header: BlockHeader=None) -> Iterator[BaseBlock]:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_block(self) -> BaseBlock:
        raise NotImplementedError("Chain classes must implement this method")

    def get_block_by_hash(self, block_hash: Hash32) -> BaseBlock:
        raise NotImplementedError("Chain classes must implement this method")

    def get_block_by_header(self, block_header: BlockHeader) -> BaseBlock:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_canonical_block_by_number(self, block_number: BlockNumber) -> BaseBlock:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def get_canonical_block_hash(self, block_number):
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

    #
    # Validation API
    #
    @abstractmethod
    def validate_block(self, block: BaseBlock) -> None:
        raise NotImplementedError("Chain classes must implement this method")

    @abstractmethod
    def validate_gaslimit(self, header: BlockHeader) -> None:
        raise NotImplementedError("Chain classes must implement this method")


class Chain(BaseChain):
    """
    A Chain is a combination of one or more VM classes.  Each VM is associated
    with a range of blocks.  The Chain class acts as a wrapper around these other
    VM classes, delegating operations to the appropriate VM depending on the
    current block number.
    """
    logger = logging.getLogger("evm.chain.chain.Chain")
    header = None  # type: BlockHeader
    network_id = None  # type: int
    gas_estimator = None  # type: Callable
    queue_block = None
    vm = None
    _journaldb = None
    num_journal_records_for_block_import = 0
    
    chaindb_class = ChainDB  # type: Type[BaseChainDB]
    chain_head_db_class = ChainHeadDB

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
        self.chaindb = self.get_chaindb_class()(self.db, self.wallet_address)
        self.chain_head_db = self.get_chain_head_db_class().load_from_saved_root_hash(self.db)
        
        try:
            self.header = self.create_header_from_parent(self.get_canonical_head())
        except CanonicalHeadNotFound:
            #this is a new block, lets make a genesis block
            self.logger.debug("Creating new genesis block on chain {}".format(self.wallet_address))
            self.header = self.get_vm_class_for_block_timestamp().create_genesis_block().header
            
        self.queue_block = self.get_block()
        
        if self.gas_estimator is None:
            self.gas_estimator = get_gas_estimator()  # type: ignore
      
    def reinitialize(self):
        self.__init__(self.db, self.wallet_address, self.private_key)
        
    def set_new_wallet_address(self, wallet_address: Address, private_key: BaseKey=None):
        self.wallet_address = wallet_address
        self.private_key = private_key
        self.reinitialize()
        
    
    #
    # Global Record and discard API
    # 
    def enable_journal_db(self):
        if self._journaldb is None:
            self.base_db = self.db
            self._journaldb = JournalDB(self.base_db)
            #we keep the name self.db so that all of the functions still work, but at this point it is a journaldb.
            self.base_db = self._journaldb
            
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
    def get_chain_head_db_class(cls) -> Type[BaseChainDB]:
        if cls.chain_head_db_class is None:
            raise AttributeError("`chaindb_class` not set")
        return cls.chain_head_db_class
    
    @classmethod
    def get_genesus_wallet_address(cls) -> Type[BaseChainDB]:
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
        chaindb = cls.get_chaindb_class()(base_db, wallet_address = wallet_address)
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
        
        chaindb = cls.get_chaindb_class()(base_db, wallet_address = cls.genesis_wallet_address)
        chaindb.persist_header(genesis_header)
        
        chain_head_db = cls.get_chain_head_db_class()(base_db)
        
        window_for_this_block = math.ceil(genesis_header.timestamp/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
        chain_head_db.set_chain_head_hash(cls.genesis_wallet_address, genesis_header.hash)
        chain_head_db.initialize_historical_root_hashes(chain_head_db.root_hash, window_for_this_block)
        chain_head_db.persist(save_current_root_hash = True, save_root_hash_timestamps = False)
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
    def get_vm(self, header: BlockHeader=None, refresh = True) -> 'BaseVM':
        """
        Returns the VM instance for the given block number.
        """
        if header is None or header == self.header:
            if self.vm is None or refresh:
                header = self.header
                vm_class = self.get_vm_class_for_block_timestamp(header.timestamp)
                self.vm = vm_class(header=header, chaindb=self.chaindb, wallet_address = self.wallet_address, private_key=self.private_key, network_id=self.network_id)
            return self.vm
        else:
            vm_class = self.get_vm_class_for_block_timestamp(header.timestamp)
        
            return vm_class(header=header, chaindb=self.chaindb, wallet_address = self.wallet_address, private_key=self.private_key, network_id=self.network_id)

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

    def get_canonical_head(self):
        """
        Returns the block header at the canonical chain head.

        Raises CanonicalHeadNotFound if there's no head defined for the canonical chain.
        """
        return self.chaindb.get_canonical_head()


    #
    # Block API
    #
    @to_tuple
    def get_ancestors(self, limit: int, header: BlockHeader=None) -> Iterator[BaseBlock]:
        """
        Return `limit` number of ancestor blocks from the current canonical head.
        """
        if header is None:
            header = self.header
        lower_limit = max(header.block_number - limit, 0)
        for n in reversed(range(lower_limit, header.block_number)):
            yield self.get_canonical_block_by_number(BlockNumber(n))

    def get_block(self) -> BaseBlock:
        """
        Returns the current TIP block.
        """
        return self.get_vm().block

    def get_block_by_hash(self, block_hash: Hash32) -> BaseBlock:
        """
        Returns the requested block as specified by block hash.
        """
        validate_word(block_hash, title="Block Hash")
        block_header = self.get_block_header_by_hash(block_hash)
        return self.get_block_by_header(block_header)

    def get_block_by_header(self, block_header):
        """
        Returns the requested block as specified by the block header.
        """
        vm = self.get_vm(block_header)
        return vm.block

    def get_canonical_block_by_number(self, block_number: BlockNumber) -> BaseBlock:
        """
        Returns the block with the given number in the canonical chain.

        Raises BlockNotFound if there's no block with the given number in the
        canonical chain.
        """
        validate_uint256(block_number, title="Block Number")
        return self.get_block_by_hash(self.chaindb.get_canonical_block_hash(block_number))

    def get_canonical_block_hash(self, block_number: BlockNumber) -> Hash32:
        """
        Returns the block hash with the given number in the canonical chain.

        Raises BlockNotFound if there's no block with the given number in the
        canonical chain.
        """
        return self.chaindb.get_canonical_block_hash(block_number)
    
    #
    # Blockchain Database API
    #
    def save_chain_head_hash_to_trie_for_time_period(self,block_header, propogate_to_present = True):
        timestamp = block_header.timestamp
        currently_saving_window = int(time.time()/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
        if timestamp <= currently_saving_window:
            #we have to go back and put it into the correct window, and update all windows after that
            #lets only keep the past NUMBER_OF_HEAD_HASH_TO_SAVE block_head_root_hash
            window_for_this_block = math.ceil(timestamp/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
            if propogate_to_present:
                self.chain_head_db.add_block_hash_to_timestamp(self.wallet_address, block_header.hash, window_for_this_block)
            else:
                self.chain_head_db.add_block_hash_to_timestamp_without_propogating_to_present(self.wallet_address, block_header.hash, window_for_this_block)

    

        
    #
    # Queueblock API
    #
    def add_transaction_to_queue_block(self, transaction) -> None:
        if self.queue_block is None:
            self.queue_block = self.get_block()
            
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
                VM.get_transaction_class(),
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
        
        #self.logger.debug("creating transaction with nonce {}".format(tx_nonce))
        transaction = self.create_and_sign_transaction(nonce = tx_nonce, *args, **kwargs)
        
#        from evm.utils.rlp import convert_rlp_to_correct_class
#        
#        from evm.rlp.transactions import BaseTransaction
#        class P2PSendTransaction(rlp.Serializable):
#            fields = BaseTransaction._meta.fields
#        transaction = convert_rlp_to_correct_class(P2PSendTransaction, transaction)
        
        self.add_transactions_to_queue_block(transaction)
        return transaction
    
    def get_current_queue_block_nonce(self):
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

    def get_receivable_transactions(self, address):
        #from evm.rlp.accounts import TransactionKey
        tx_keys = self.get_vm().state.account_db.get_receivable_transactions(address)
        if len(tx_keys) == 0:
            return False, False
        transactions = []
        for tx_key in tx_keys:
            tx = self.get_canonical_transaction(tx_key.transaction_hash)
            transactions.append(tx)
        return transactions, tx_keys
    
    def create_receivable_signed_transactions(self):
        transactions, tx_keys = self.get_receivable_transactions(self.wallet_address)
        
        if transactions == False:
            return []
        receive_transactions = []
        for i, tx in enumerate(transactions):
            re_tx = self.get_vm().create_receive_transaction(
                    sender_block_hash = tx_keys[i].sender_block_hash, 
                    transaction=tx, 
                    v=0,
                    r=0,
                    s=0,
                    )
            re_tx = re_tx.get_signed(self.private_key, self.network_id)
            receive_transactions.append(re_tx)
        return receive_transactions
    
    def populate_queue_block_with_receive_tx(self):
        receive_tx = self.create_receivable_signed_transactions()
        self.add_transactions_to_queue_block(receive_tx)
        return receive_tx
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
            time_wait = self.get_vm(refresh=False).check_wait_before_new_block(block)
            if time_wait > 0:
                if isinstance(block, self.get_vm(refresh=False).get_queue_block_class()):
                    self.logger.debug("not enough time between blocks. We require {0} seconds. Since it is a queueblock, we will wait for {1} seconds and then import.".format(constants.MIN_TIME_BETWEEN_BLOCKS, time_wait))
                    time.sleep(time_wait)
                else:
                    raise NotEnoughTimeBetweenBlocks()     
        return
    
    #
    # Reverting block functions
    #
    
    def delete_canonical_chain(self, wallet_address, vm):
        self.chain_head_db.delete_chain(wallet_address)
        self.chaindb.delete_canonical_chain(wallet_address)
        vm.state.clear_account_keep_receivable_transactions_and_persist(wallet_address)
        
    def set_parent_as_canonical_head(self, existing_block_header, wallet_address, vm):
        block_parent_header = self.chaindb.get_block_header_by_hash(existing_block_header.parent_hash)
        self.save_chain_head_hash_to_trie_for_time_period(block_parent_header)
        self.chain_head_db.set_chain_head_hash(wallet_address, block_parent_header.hash)
        self.chaindb._set_as_canonical_chain_head(block_parent_header, wallet_address = wallet_address)
        vm.state.revert_account_to_hash_keep_receivable_transactions_and_persist(block_parent_header.account_hash, wallet_address)
        
    def revert_block(self, descendant_block_hash, vm):
        descendant_block_header = self.chaindb.get_block_header_by_hash(descendant_block_hash)
        self.chain_head_db.delete_block_hash_from_chronological_window(descendant_block_hash, descendant_block_header.timestamp)
        self.chaindb.remove_block_from_all_parent_child_lookups(descendant_block_header, vm.get_block_class().receive_transaction_class)
        self.chaindb.delete_all_block_children(descendant_block_hash)
        
        #for every one, re-add pending receive transaction for all receive transactions only if sending block still exists
        #make all blocks unprocessed so that receivable transactions are not saved that came from one of the non-canonical blocks.
        vm.reverse_pending_transactions(descendant_block_header)

        self.chaindb.save_unprocessed_block_lookup(descendant_block_hash)
        
    
    def purge_block_and_all_children_and_set_parent_as_chain_head(self, existing_block_header, wallet_address = None):
        if wallet_address is not None:
            #we need to re-initialize the chain for the new wallet address.
            if wallet_address != self.wallet_address:
                self.logger.debug("setting new wallet address for chain")
                self.set_new_wallet_address(wallet_address = wallet_address)
                
        self.get_vm()
        if existing_block_header.block_number == 0:
            self.delete_canonical_chain(self.wallet_address, self.get_vm(refresh = False))
        else:
            #set the parent block as the new canonical head, and handle all the data for that
            self.set_parent_as_canonical_head(existing_block_header, self.wallet_address, self.get_vm(refresh = False))

        #1) delete chronological transactions, delete everything from chronological root hashes, delete children lookups
        all_descendant_block_hashes = self.chaindb.get_all_descendant_block_hashes(existing_block_header.hash)
        
        #first set all of the new chain heads and all the data that goes along with them
        if all_descendant_block_hashes is not None:
            for descendant_block_hash in all_descendant_block_hashes:
                descendant_block_header = self.chaindb.get_block_header_by_hash(descendant_block_hash)
                descendant_wallet_address = self.chaindb.get_chain_wallet_address_for_block_hash(self.chaindb.db, descendant_block_hash)
                
                if descendant_block_header.parent_hash not in all_descendant_block_hashes:
                    #this is the new head of a chain. set it as the new head for chronological root hashes
                    #except for children in this chain, because it will be off by 1 block. we already set this earlier
                    
                    descendant_wallet_address = self.chaindb.get_chain_wallet_address_for_block_hash(self.chaindb.db, descendant_block_hash)
                       
                    if descendant_wallet_address != self.wallet_address:
                        if descendant_block_header.block_number == 0:
                            self.delete_canonical_chain(descendant_wallet_address, self.get_vm(refresh = False))
                        else:
                            self.set_parent_as_canonical_head(descendant_block_header, self.wallet_address, self.get_vm(refresh = False))
                 
        #now we know what the new heads are, so we can deal with the rest of the descendants
        if all_descendant_block_hashes is not None:
            for descendant_block_hash in all_descendant_block_hashes:
                self.revert_block(descendant_block_hash, self.get_vm(refresh = False))
        
        self.revert_block(existing_block_header.hash, self.get_vm(refresh = False))
        
        #persist changes
        self.get_vm(refresh = False).state.account_db.persist()
        self.chain_head_db.persist(True)
        
        
    def import_chronological_block_window(self, block_list, window_start_timestamp, save_block_head_hash_timestamp = True, allow_unprocessed=False, propogate_block_head_hash_timestamp_to_present = True):
        validate_uint256(window_start_timestamp, title='timestamp')

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
                block_header_to_delete = self.chaindb.get_block_header_by_hash(block_hash_to_delete)
                block_wallet_address = self.chaindb.get_chain_wallet_address_for_block_hash(self.chaindb.db, block_hash_to_delete)
                if not self.chaindb.is_block_unprocessed(block_hash_to_delete) and self.chaindb.exists(block_hash_to_delete):
                    self.purge_block_and_all_children_and_set_parent_as_chain_head(block_header_to_delete, wallet_address = block_wallet_address)
    
        if len(block_list) > 0:
            self.logger.debug("starting block import for chronological block window")
            #if block list is empty, load the local historical root hashes and delete them all
            for block in block_list:
                wallet_address = self.chaindb.get_chain_wallet_address_for_block(block)
                self.import_block(block, wallet_address = wallet_address, save_block_head_hash_timestamp = save_block_head_hash_timestamp, allow_unprocessed=False, propogate_block_head_hash_timestamp_to_present = propogate_block_head_hash_timestamp_to_present)
        else:
            self.logger.debug("importing an empty chronological window. going to make sure we have a saved historical root hash")
            historical_root_hashes = self.chain_head_db.get_historical_root_hashes()
            if historical_root_hashes is not None:
                historical_root_hashes_dict = dict(historical_root_hashes)
                if (window_start_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE) not in historical_root_hashes_dict:
                    try:
                        self.chain_head_db.propogate_previous_historical_root_hash_to_timestamp(window_start_timestamp + TIME_BETWEEN_HEAD_HASH_SAVE)
                    except AppendHistoricalRootHashTooOld:
                        self.logger.debug("Tried to propogate the previous historical root hash but there was none. This shouldn't happen")
                        
    
    def import_chain(self, block_list, perform_validation: bool=True, save_block_head_hash_timestamp = True, propogate_block_head_hash_timestamp_to_present = True):
        self.logger.debug("importing chain")
        
        #if we are given a block that is not one of the two allowed classes, try converting it.
        if len(block_list) > 0 and not isinstance(block_list[0], self.get_vm().get_block_class()):
            self.logger.debug("converting chain to correct class")
            corrected_block_list = []
            for block in block_list:
                corrected_block = self.get_vm().convert_block_to_correct_class(block)
                corrected_block_list.append(corrected_block)
            block_list = corrected_block_list
            
        #the wallet address is always the sender of the genesis block. Even for smart contracts
        wallet_address = block_list[0].header.sender
        for block in block_list:
            self.import_block(block, 
                              perform_validation = perform_validation, 
                              save_block_head_hash_timestamp = save_block_head_hash_timestamp, 
                              wallet_address = wallet_address, 
                              propogate_block_head_hash_timestamp_to_present = propogate_block_head_hash_timestamp_to_present)
            
    def import_block(self, block: BaseBlock, 
                           perform_validation: bool=True,
                           save_block_head_hash_timestamp = True, 
                           wallet_address = None, 
                           allow_unprocessed = True, 
                           allow_replacement = True, 
                           propogate_block_head_hash_timestamp_to_present = True) -> BaseBlock:
        """
        Imports a complete block.
        """
        if wallet_address is not None:
            #we need to re-initialize the chain for the new wallet address.
            if wallet_address != self.wallet_address:
                self.logger.debug("setting new wallet address for chain")
                self.set_new_wallet_address(wallet_address = wallet_address)
                
        #if we are given a block that is not one of the two allowed classes, try converting it.
        if not isinstance(block, self.get_vm(refresh=False).get_block_class()):
            self.logger.debug("converting block to correct class")
            block = self.get_vm(refresh=False).convert_block_to_correct_class(block)
        
        if not isinstance(block, self.get_vm(refresh=False).get_queue_block_class()) and block.sender == self.genesis_wallet_address and block.header.block_number == 0:
            self.logger.debug("Tried to import a new genesis block on the genesis chain. This is not allowed")
            return
            #raise TriedImportingGenesisBlock("Tried to import a new genesis block on the genesis chain. This is not allowed")
        
            
        if block.number > self.header.block_number:
            if not allow_unprocessed:
                raise UnprocessedBlockNotAllowed()
            #we can allow this for unprocessed blocks as long as we have the parent in our database
            if self.chaindb.exists(block.header.parent_hash):
                #save as unprocessed
                return self.save_block_as_unprocessed(block)
            raise ValidationError(
                "Attempt to import block #{0}.  Cannot import block with number "
                "greater than queueblock #{1}.".format(
                    block.number,
                    self.header.block_number,
                )
            )
        

        
        journal_enabled = False
        if block.number < self.header.block_number:
            if not allow_replacement:
                raise ReplacingBlocksNotAllowed()
            self.logger.debug("went into block replacing mode")
            self.logger.debug("block.number = {}, self.header.block_number = {}".format(block.number,self.header.block_number))
            self.logger.debug("this chains wallet address = {}, this block's sender = {}".format(self.wallet_address, block.sender))

            existing_block_header = self.chaindb.get_canonical_block_header_by_number(block.number, self.wallet_address)

            if existing_block_header.hash == block.header.hash:
                self.logger.debug("tried to import a block that has a hash that matches the local block. no import required.")                    
                return
            else:
                
                self.enable_journal_db()
                journal_record = self.record_journal()
                journal_enabled = True
                self.num_journal_records_for_block_import += 1
                self.purge_block_and_all_children_and_set_parent_as_chain_head(existing_block_header)
                #refresh vm
#                self.get_vm()
#                
#                if block.number == 0:
#                    self.delete_canonical_chain(self.wallet_address, self.get_vm(refresh = False))
#                else:
#                    #set the parent block as the new canonical head, and handle all the data for that
#                    self.set_parent_as_canonical_head(existing_block_header, self.wallet_address, self.get_vm(refresh = False))
#
#                #1) delete chronological transactions, delete everything from chronological root hashes, delete children lookups
#                all_descendant_block_hashes = self.chaindb.get_all_descendant_block_hashes(existing_block_header.hash)
#                
#                #first set all of the new chain heads and all the data that goes along with them
#                if all_descendant_block_hashes is not None:
#                    for descendant_block_hash in all_descendant_block_hashes:
#                        descendant_block_header = self.chaindb.get_block_header_by_hash(descendant_block_hash)
#                        descendant_wallet_address = self.chaindb.get_chain_wallet_address_for_block_hash(self.chaindb.db, descendant_block_hash)
#                        
#                        if descendant_block_header.parent_hash not in all_descendant_block_hashes:
#                            #this is the new head of a chain. set it as the new head for chronological root hashes
#                            #except for children in this chain, because it will be off by 1 block. we already set this earlier
#                            
#                            descendant_wallet_address = self.chaindb.get_chain_wallet_address_for_block_hash(self.chaindb.db, descendant_block_hash)
#                               
#                            if descendant_wallet_address != self.wallet_address:
#                                if descendant_block_header.block_number == 0:
#                                    self.delete_canonical_chain(descendant_wallet_address, self.get_vm(refresh = False))
#                                else:
#                                    self.set_parent_as_canonical_head(descendant_block_header, self.wallet_address, self.get_vm(refresh = False))
#                         
#                #now we know what the new heads are, so we can deal with the rest of the descendants
#                if all_descendant_block_hashes is not None:
#                    for descendant_block_hash in all_descendant_block_hashes:
#                        self.revert_block(descendant_block_hash, self.get_vm(refresh = False))
#                
#                self.revert_block(existing_block_header.hash, self.get_vm(refresh = False))
#                
#                #persist changes
#                self.get_vm(refresh = False).state.account_db.persist()
#                self.chain_head_db.persist(True)
                
        
        self.logger.debug("importing block number {}".format(block.number))
        
        
        self.validate_time_between_blocks(block)
            
        if isinstance(block, self.get_vm(refresh=False).get_queue_block_class()):
            # If it was a queueblock, then the header will have changed after importing
            perform_validation = False
            
        
        try:    
            if not self.chaindb.is_block_unprocessed(block.header.parent_hash):
                #this part checks to make sure the parent exists
                try:
                    imported_block = self.get_vm(block.header).import_block(block)
                   
                    
                    # Validate the imported block.
                    if perform_validation:
                        ensure_imported_block_unchanged(imported_block, block)
                        self.validate_block(imported_block)
    
                    
                    self.chain_head_db.set_chain_head_hash(self.wallet_address, imported_block.header.hash)
                    self.chain_head_db.persist(True, save_root_hash_timestamps = save_block_head_hash_timestamp)
                    if save_block_head_hash_timestamp:
                        self.chain_head_db.add_block_hash_to_chronological_window(imported_block.header.hash, imported_block.header.timestamp)
                        self.save_chain_head_hash_to_trie_for_time_period(imported_block.header, propogate_block_head_hash_timestamp_to_present)
                    self.chaindb.persist_block(imported_block)
                    
                    #remove any unprocessed flags for this block so that the children can be processed.
                    self.chaindb.delete_unprocessed_block_lookup(imported_block.hash)
                    
                    self.header = self.create_header_from_parent(self.get_canonical_head())
                    self.queue_block = None
                    self.logger.debug(
                        'IMPORTED_BLOCK: number %s | hash %s',
                        imported_block.number,
                        encode_hex(imported_block.hash),
                    )
                    self.import_unprocessed_children(imported_block)
    
                    
                    #finally, remove unprocessed database lookups for this block
                    self.chaindb.delete_unprocessed_children_blocks_lookup(imported_block.hash)
                    
                    
                    return_block = imported_block
                    
                except ReceivableTransactionNotFound:
                    if not allow_unprocessed:
                        raise UnprocessedBlockNotAllowed()
                    return_block = self.save_block_as_unprocessed(block)
            else:
                if not allow_unprocessed:
                    raise UnprocessedBlockNotAllowed()
                return_block = self.save_block_as_unprocessed(block)
                
        except Exception as e:
            if journal_enabled:
                self.logger.debug('discarding journal')
                self.discard_journal(journal_record)
                self.num_journal_records_for_block_import -= 1
            raise e
            
        if journal_enabled:
            self.logger.debug('commiting journal')
            self.commit_journal(journal_record)
            self.num_journal_records_for_block_import -= 1
            if self.num_journal_records_for_block_import == 0:
                #only persist if there are no more journal records left to commit
                self.persist_journal()
        return return_block
                            
    #used for fast sync
    def import_block_no_verification(self, block: BaseBlock, wallet_address = None) -> None:
        """
        Imports a complete block. with no verification
        """
   
        #if we are given a block that is not one of the two allowed classes, try converting it.
        if not isinstance(block, self.get_vm(refresh=False).get_block_class()) and not isinstance(block, self.get_vm(refresh=False).get_queue_block_class()):
            self.logger.debug("converting block to correct class")
            block = self.get_vm(refresh=False).convert_block_to_correct_class(block)
            
        if block.sender == self.genesis_wallet_address and block.header.block_number == 0:
            raise TriedImportingGenesisBlock("Tried to import a new genesis block on the genesis chain. This is not allowed")
            
        if wallet_address is not None:
            #we need to re-initialize the chainfor the new wallet address.
            if wallet_address != self.wallet_address:
                self.logger.debug("setting new wallet address for chain")
                self.set_new_wallet_address(wallet_address = wallet_address)
        if block.number > self.header.block_number:
            raise ValidationError(
                "Attempt to import block #{0}.  Cannot import block with number "
                "greater than queueblock #{1}.".format(
                    block.number,
                    self.header.block_number,
                )
            )
        
        if block.number < self.header.block_number:
            #TODO: load chain at that block, check if the hash matches. if it does, then do nothing.
            #if the hash doesnt match, then reverse transactions of block and all children, and replace the block with this one.
            pass
        if not self.chaindb.is_block_unprocessed(block.header.parent_hash):
            try:
                imported_block = self.get_vm(block.header).import_block_no_verification(block)
                self.chain_head_db.set_chain_head_hash(self.wallet_address, imported_block.header.hash)
                self.chain_head_db.persist(save_current_root_hash = True, save_root_hash_timestamps = False)
        
                self.chaindb.persist_block(imported_block)
                #remove any unprocessed flags for this block so that the children can be processed.
                self.chaindb.delete_unprocessed_block_lookup(imported_block.hash)
                    
                self.header = self.create_header_from_parent(self.get_canonical_head())
                self.queue_block = None
                self.logger.debug(
                    'FAST_IMPORTED_BLOCK: number %s | hash %s',
                    imported_block.number,
                    encode_hex(imported_block.hash),
                )
    
                self.import_unprocessed_children(imported_block)
                
                #finally, remove unprocessed database lookups for this block
                self.chaindb.delete_unprocessed_children_blocks_lookup(imported_block.hash)
                
                
            except ReceivableTransactionNotFound:
                self.save_block_as_unprocessed(block)
        else:
            self.logger.debug("failed because parent wasn't processed")
            return self.save_block_as_unprocessed(block)
        
        
    def import_unprocessed_children(self, block):
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
                            child_wallet_address = self.chaindb.get_chain_wallet_address_for_block_hash(self.chaindb.db, child_block_hash)
                            #child_chain = Chain(self.base_db, child_wallet_address)
                            #get block
                            child_block = self.chaindb.get_block_by_hash(child_block_hash, self.get_vm(refresh=False).get_block_class())
                            self.import_block(child_block, wallet_address = child_wallet_address)
                        except Exception as e:
                            self.logger.error("Tried to import an unprocessed child block and got this error {}".format(e))
                            #raise e
                            pass
                        
                        
    def save_block_as_unprocessed(self, block):
        #before adding to unprocessed blocks, make sure the receive transactions are valid
        for receive_transaction in block.receive_transactions:
            #there must be at least 1 to get this far
            receive_transaction.validate()
            
        #now we add it to unprocessed blocks
        self.chaindb.save_block_as_unprocessed(block)
    
        
        
        #save the transactions to db
        vm = self.get_vm(refresh=False)
        vm.save_items_to_db_as_trie(block.transactions, block.header.transaction_root)
        vm.save_items_to_db_as_trie(block.receive_transactions, block.header.receive_transaction_root)
        
        #we don't want to persist because that will add it to the canonical chain. 
        #We just want to save it to the database so we can process it later if needbe.
        self.chaindb.persist_non_canonical_block(block)
        #self.chaindb.persist_block(block)
        
        try:
            self.header = self.create_header_from_parent(self.get_canonical_head())
        except CanonicalHeadNotFound:
            self.header = self.get_vm_class_for_block_timestamp().create_genesis_block().header
            
        self.queue_block = None
        
        self.logger.debug(
            'SAVED_BLOCK_AS_UNPROCESSED: number %s | hash %s',
            block.number,
            encode_hex(block.hash),
        )
        return block
        
    def import_current_queue_block(self):
        
        return self.import_block(self.queue_block)
    
    def get_all_chronological_blocks_for_window(self, window_timestamp):
        validate_uint256(window_timestamp, title='timestamp')
        chronological_blocks = self.chain_head_db.load_chronological_block_window(window_timestamp)
        if chronological_blocks is None:
            return None
        else:
            list_of_blocks = []
            for chronological_block in chronological_blocks:
                block_hash = chronological_block[1]
                new_block = self.chaindb.get_block_by_hash(block_hash, self.get_vm().get_block_class())
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


    #
    # Stake API
    #
    #this doesnt count the stake of the origin chain
    def get_block_stake_from_children(self, block_hash, exclude_chains = None):
        validate_word(block_hash, title="Block Hash")
        
        children_chain_wallet_addresses = self.chaindb.get_block_children_chains(block_hash, exclude_chains)
        self.logger.debug("get_block_stake_from_children. children wallet addresses: {}".format(children_chain_wallet_addresses))
        
        if children_chain_wallet_addresses is None:
            return 0
        else:
            total_stake = 0
            for wallet_address in children_chain_wallet_addresses:
               total_stake += self.get_mature_stake(wallet_address)
            return total_stake
                
                       
    def get_mature_stake(self, wallet_address = None):
        if wallet_address is None:
            wallet_address = self.wallet_address
            
        validate_canonical_address(wallet_address, title="Wallet Address")
        #get account balance
        account_balance = self.get_vm().state.account_db.get_balance(wallet_address)
        #subtract immature coins (look at receive only)
        
        try:
            immature_coins = self.get_immature_receive_balance(wallet_address)
        except CanonicalHeadNotFound:
            return 0
        
        mature_stake = account_balance-immature_coins
        #this can be negative if they spent their received coins. Lets bottom it out at 0
        if mature_stake < 0:
            mature_stake = 0
            
        return mature_stake
    
    
    def get_immature_receive_balance(self, wallet_address = None):
        if wallet_address is None:
            wallet_address = self.wallet_address
        
        validate_canonical_address(wallet_address, title="Wallet Address")
   
        canonical_head = self.chaindb.get_canonical_head(wallet_address = wallet_address)

        total = 0
        transaction_class =  self.get_block().receive_transaction_class
        if canonical_head.timestamp < int(time.time()) - COIN_MATURE_TIME_FOR_STAKING:
            return total
        else:
            block_receive_transactions = self.chaindb.get_block_receive_transactions(canonical_head,transaction_class)
            for transaction in block_receive_transactions:
                total += transaction.transaction.value
        
        previous_header = canonical_head
        while True:
            if previous_header.parent_hash == constants.GENESIS_PARENT_HASH:
                break
            
            parent_header = self.chaindb.get_block_header_by_hash(previous_header.parent_hash)
            
            if parent_header.timestamp < int(time.time()) - COIN_MATURE_TIME_FOR_STAKING:
                break
            block_receive_transactions = self.chaindb.get_block_receive_transactions(parent_header,transaction_class)
            for transaction in block_receive_transactions:
                total += transaction.transaction.value
            
            previous_header = parent_header
        
        return total
    
    #
    # Min Block Gas API used for throttling the network
    #
    
    def update_current_network_tpc_capability(self, current_network_tpc_cap, update_min_gas_price = True):
        validate_uint256(current_network_tpc_cap, title="current_network_tpc_cap")
        self.chaindb.save_current_historical_network_tpc_capability(current_network_tpc_cap)
        
        if update_min_gas_price:
            current_centisecond = int(time.time()/100) * 100
            timestamp_min_gas_price_updated = self.update_tpc_from_chronological(update_min_gas_price = True)
            
            if timestamp_min_gas_price_updated > current_centisecond:
                self.chaindb.recalculate_historical_mimimum_gas_price(current_centisecond)
            
        
        
    
    def update_tpc_from_chronological(self, update_min_gas_price = True):
        #start at the newest window, if the same tps stop. but if different tps keep going back
        current_historical_window = int(time.time()/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
        current_centisecond = int(time.time()/100) * 100
        
        
        
        
        for historical_window_timestamp in range(current_historical_window,
                                                 current_historical_window-NUMBER_OF_HEAD_HASH_TO_SAVE*TIME_BETWEEN_HEAD_HASH_SAVE, 
                                                 -TIME_BETWEEN_HEAD_HASH_SAVE):
        
            tpc_sum_dict = {}
            chronological_block_window = self.chain_head_db.load_chronological_block_window(historical_window_timestamp)
            
            self.logger.debug('loading chronological block window for timestamp {}'.format(historical_window_timestamp))
            #zero the dictionary
            if historical_window_timestamp+TIME_BETWEEN_HEAD_HASH_SAVE < current_centisecond:
                end = historical_window_timestamp
            else:
                end = current_centisecond
                
            for timestamp in range(historical_window_timestamp, end+100, 100):
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
            self.chaindb.recalculate_historical_mimimum_gas_price(historical_window_timestamp+TIME_BETWEEN_HEAD_HASH_SAVE)
            
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
            difference_found = True
        else:
            hist_tpc_dict = dict(hist_tpc)
            for timestamp, tpc in new_hist_tpc_dict.items():
                if timestamp not in hist_tpc_dict or hist_tpc_dict[timestamp] != tpc:
                    difference_found = True
                hist_tpc_dict[timestamp] = tpc
            hist_tpc = list(hist_tpc_dict.items())
            
        
        #save it to db
        self.chaindb.save_historical_tx_per_centisecond(hist_tpc, de_sparse = False)
        
        return not difference_found
            
    
    def get_local_tpc_cap(self):
        #base it on the time it takes to import a block
        
        from evm.db.backends.memory import MemoryDB
        from evm import MainnetChain
        from evm.chains.mainnet import (
            MAINNET_TPC_CAP_TEST_GENESIS_PARAMS,
            MAINNET_TPC_CAP_TEST_GENESIS_STATE,
            TPC_CAP_TEST_GENESIS_PRIVATE_KEY,
        )
        from evm.constants import random_private_keys
                
        db = MemoryDB()
        chain = MainnetChain.from_genesis(db, 
                                          TPC_CAP_TEST_GENESIS_PRIVATE_KEY.public_key.to_canonical_address(), 
                                          MAINNET_TPC_CAP_TEST_GENESIS_PARAMS, 
                                          MAINNET_TPC_CAP_TEST_GENESIS_STATE, 
                                          private_key = TPC_CAP_TEST_GENESIS_PRIVATE_KEY)
        
        receiver_privkey = keys.PrivateKey(random_private_keys[0])
        
        chain.create_and_sign_transaction_for_queue_block(
                    gas_price=0x01,
                    gas=0x0c3500,
                    to=receiver_privkey.public_key.to_canonical_address(),
                    value=1000,
                    data=b"",
                    v=0,
                    r=0,
                    s=0
                    )
        
        start_time = time.time()
        chain.import_current_queue_block()
        duration = time.time()-start_time
        tx_per_centisecond = 100/duration
        return tx_per_centisecond
        
#    def group_into_centiseconds(self, time_item_data):
#        if not (isinstance(time_item_data, list) or isinstance(time_item_data, tuple)):
#            raise ValidationError("cant group into centiseconds because it isnt a list or tuple")
#        
#        if len(time_item_data) == 0:
#            return time_item_data
#        
        
    
        
#    def get_required_block_gas_price(self, timestamp, average_max_transaction_rate):
#        #needs to be based on a time where we are gauranteed to have consensus. 
#        #needs a very low probability of being modified by new blocks.
#        #this will also give someone a 15 minute window to hammer the network with
#        #a huge number of transactions. So should be conservative at first.
#        
#        
#        #only calculate each minute. If it has already been calculated this minute, look up in db
#        historical_
        
        
        
    
    
# This class is a work in progress; its main purpose is to define the API of an asyncio-compatible
# Chain implementation.
class AsyncChain(Chain):

    async def coro_import_block(self,
                                block: BlockHeader,
                                perform_validation: bool=True) -> BaseBlock:
        raise NotImplementedError()
