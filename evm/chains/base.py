from __future__ import absolute_import

from abc import (
    ABCMeta,
    abstractmethod
)
import time
import math
import operator
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
from evm.constants import (
    BLANK_ROOT_HASH,
    NUMBER_OF_HEAD_HASH_TO_SAVE,
    TIME_BETWEEN_HEAD_HASH_SAVE,
    COIN_MATURE_TIME_FOR_STAKING,
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
    NotEnoughTimeBetweenBlocks,
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
    
        self.private_key = private_key
        self.wallet_address = wallet_address
        self.chaindb = self.get_chaindb_class()(base_db, self.wallet_address)
        self.chain_head_db = self.chain_head_db_class.load_from_saved_root_hash(base_db)
        
        try:
            self.header = self.create_header_from_parent(self.get_canonical_head())
        except CanonicalHeadNotFound:
            #this is a new block, lets make a genesis block
            self.logger.debug("Creating new genesis block on chain {}".format(self.wallet_address))
            self.header = self.get_vm_class_for_block_timestamp().create_genesis_block().header
            
        self.queue_block = self.get_block()
        
        if self.gas_estimator is None:
            self.gas_estimator = get_gas_estimator()  # type: ignore
        
    #
    # Helpers
    #
    @classmethod
    def get_chaindb_class(cls) -> Type[BaseChainDB]:
        if cls.chaindb_class is None:
            raise AttributeError("`chaindb_class` not set")
        return cls.chaindb_class
    
        
        
    #
    # Chain API
    #
    @classmethod
    def from_genesis(cls,
                     base_db: BaseDB,
                     wallet_address: Address,
                     private_key: BaseKey,
                     genesis_params: Dict[str, HeaderParams],
                     genesis_state: AccountState=None,
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
        account_db.persist()
        

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
        signed_genesis_header = genesis_header.get_signed(private_key, cls.network_id)
        chaindb = cls.get_chaindb_class()(base_db, wallet_address = wallet_address)
        chaindb.persist_header(signed_genesis_header)
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
        if header is None:
            header = self.header
            
        vm_class = self.get_vm_class_for_block_timestamp(header.timestamp)
        
        return vm_class(header=header, chaindb=self.chaindb, private_key=self.private_key, network_id=self.network_id)

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
    def save_chain_head_hash_to_trie_for_time_period(self,block_header):
        timestamp = block_header.timestamp
        currently_saving_window = int(time.time()/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
        if timestamp <= currently_saving_window:
            #we have to go back and put it into the correct window, and update all windows after that
            #lets only keep the past NUMBER_OF_HEAD_HASH_TO_SAVE block_head_root_hash
            window_for_this_block = math.ceil(timestamp/TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
            self.chain_head_db.add_block_hash_to_timestamp(self.wallet_address, block_header.hash, window_for_this_block)
    

        
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

    def import_block(self, block: BaseBlock, perform_validation: bool=True, save_block_head_hash_timestamp = True) -> BaseBlock:
        """
        Imports a complete block.
        """
        
        if not block.is_genesis:
            time_wait = self.get_vm().check_wait_before_new_block(block)
            if time_wait > 0:
                self.logger.debug("not enough time between blocks. We require {0} seconds. waiting for {1} seconds.".format(constants.MIN_TIME_BETWEEN_BLOCKS, time_wait))
                time.sleep(time_wait)
                
        if block.number != self.header.block_number:
            raise ValidationError(
                "Attempt to import block #{0}.  Cannot import block with number "
                "different from the queueblock #{1}.".format(
                    block.number,
                    self.header.block_number,
                )
            )
        

        imported_block = self.get_vm(block.header).import_block(block)
        
        if isinstance(block, self.get_vm().get_queue_block_class()):
            # If it was a queueblock, then the header will have changed after importing
            perform_validation = False
            
        # Validate the imported block.
        if perform_validation:
            ensure_imported_block_unchanged(imported_block, block)
            self.validate_block(imported_block)
        
        for receive_transaction in imported_block.receive_transactions:
            #make sure the sender_block_hash exists
            sender_header = self.chaindb.get_block_header_by_hash(receive_transaction.sender_block_hash)
            
        self.chain_head_db.set_chain_head_hash(self.wallet_address, imported_block.header.hash)
        self.chain_head_db.persist(True)
        if save_block_head_hash_timestamp:
            self.chain_head_db.add_block_hash_to_chronological_window(imported_block.header.hash, imported_block.header.timestamp)
            self.save_chain_head_hash_to_trie_for_time_period(imported_block.header)
        self.chaindb.persist_block(imported_block)
        self.header = self.create_header_from_parent(self.get_canonical_head())
        self.queue_block = None
        self.logger.debug(
            'IMPORTED_BLOCK: number %s | hash %s',
            imported_block.number,
            encode_hex(imported_block.hash),
        )
        return imported_block
    
    #used for fast sync
    def import_block_no_verification(self, block: BaseBlock) -> None:
        """
        Imports a complete block. with no verification
        """
   
        if block.number != self.header.block_number:
            raise ValidationError(
                "Attempt to import block #{0}.  Cannot import block with number "
                "different from the queueblock #{1}.".format(
                    block.number,
                    self.header.block_number,
                )
            )
        
        imported_block = self.get_vm(block.header).import_block_no_verification(block)
        
        self.chain_head_db.set_chain_head_hash(self.wallet_address, imported_block.header.hash)
        self.chain_head_db.persist(True)

        self.chaindb.persist_block(imported_block)
        self.header = self.create_header_from_parent(imported_block.header)
        self.queue_block = None
        self.logger.debug(
            'FAST_IMPORTED_BLOCK: number %s | hash %s',
            imported_block.number,
            encode_hex(imported_block.hash),
        )

        
    def import_current_queue_block(self):
        
        self.import_block(self.queue_block)
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
        parent_header = self.get_block_header_by_hash(header.parent_hash)
        low_bound, high_bound = compute_gas_limit_bounds(parent_header)
        if header.gas_limit < low_bound:
            raise ValidationError(
                "The gas limit on block {0} is too low: {1}. It must be at least {2}".format(
                    encode_hex(header.hash), header.gas_limit, low_bound))
        elif header.gas_limit > high_bound:
            raise ValidationError(
                "The gas limit on block {0} is too high: {1}. It must be at most {2}".format(
                    encode_hex(header.hash), header.gas_limit, high_bound))


    #
    # Stake API
    #
    #this doesnt count the stake of the origin chain
    def get_block_stake_from_children(self, block_hash):
        validate_word(block_hash, title="Block Hash")
        
        children_chain_wallet_addresses = self.chaindb.get_block_children_chains(block_hash)
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
        immature_coins = self.get_immature_receive_balance(wallet_address)
        
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
            parent_header = self.chaindb.get_block_header_by_hash(previous_header.parent_hash)            
            block_receive_transactions = self.chaindb.get_block_receive_transactions(parent_header,transaction_class)
            for transaction in block_receive_transactions:
                total += transaction.transaction.value
            
            if parent_header.timestamp < int(time.time()) - COIN_MATURE_TIME_FOR_STAKING or parent_header.parent_hash == constants.GENESIS_PARENT_HASH:
                break
            previous_header = parent_header
        
        return total
    
# This class is a work in progress; its main purpose is to define the API of an asyncio-compatible
# Chain implementation.
class AsyncChain(Chain):

    async def coro_import_block(self,
                                block: BlockHeader,
                                perform_validation: bool=True) -> BaseBlock:
        raise NotImplementedError()
