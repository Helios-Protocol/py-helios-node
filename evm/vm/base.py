from __future__ import absolute_import
from abc import (
    ABCMeta,
    abstractmethod
)
import contextlib
import functools
import logging
from typing import (  # noqa: F401
    List,
    Type,
)

import time

import rlp

from eth_bloom import (
    BloomFilter,
)

from eth_utils import (
    to_tuple,
)

from eth_hash.auto import keccak

from evm.constants import (
    GENESIS_PARENT_HASH,
    MAX_PREV_HEADER_DEPTH,
    MAX_UNCLES,
    MIN_TIME_BETWEEN_BLOCKS,
)
from evm.db.trie import make_trie_root_and_nodes
from evm.db.chain import BaseChainDB  # noqa: F401
from evm.exceptions import (
    HeaderNotFound,
    ValidationError,
    IncorrectBlockType,
    IncorrectBlockHeaderType,
    BlockOnWrongChain,
)
from evm.rlp.blocks import (  # noqa: F401
    BaseBlock,
    BaseQueueBlock,
)
from evm.rlp.transactions import (  # noqa: F401
    BaseTransaction,
    BaseReceiveTransaction
)
from evm.rlp.headers import (
    BlockHeader,
)
from evm.rlp.receipts import Receipt  # noqa: F401
from evm.utils.datatypes import (
    Configurable,
)
from evm.utils.db import (
    get_parent_header,
    get_block_header_by_hash,
)
from evm.utils.headers import (
    generate_header_from_parent_header,
)
from evm.validation import (
    validate_length_lte,
    validate_gas_limit,
    validate_private_key,
)
from evm.vm.message import (
    Message,
)
from evm.vm.state import BaseState  # noqa: F401
from eth_typing import (
    Hash32,
)
from eth_keys.datatypes import(
        BaseKey,
        PublicKey,
        PrivateKey
)

class BaseVM(Configurable, metaclass=ABCMeta):
    block = None  # type: BaseBlock
    block_class = None  # type: Type[BaseBlock]
    fork = None  # type: str
    chaindb = None  # type: BaseChainDB
    _state_class = None  # type: Type[BaseState]
    network_id = 0
    
    @abstractmethod
    def __init__(self, header, chaindb):
        pass

    #
    # Logging
    #
    @property
    @abstractmethod
    def logger(self):
        raise NotImplementedError("VM classes must implement this method")

    #
    # Execution
    #
    @abstractmethod
    def apply_transaction(self, header, transaction):
        raise NotImplementedError("VM classes must implement this method")

    @abstractmethod
    def execute_bytecode(self,
                         origin,
                         gas_price,
                         gas,
                         to,
                         sender,
                         value,
                         data,
                         code,
                         code_address=None):
        raise NotImplementedError("VM classes must implement this method")

    @abstractmethod
    def make_receipt(self, base_header, transaction, computation, state):
        """
        Generate the receipt resulting from applying the transaction.

        :param base_header: the header of the block before the transaction was applied.
        :param transaction: the transaction used to generate the receipt
        :param computation: the result of running the transaction computation
        :param state: the resulting state, after executing the computation

        :return: receipt
        """
        raise NotImplementedError("VM classes must implement this method")

    #
    # Mining
    #
    @abstractmethod
    def import_block(self, block):
        raise NotImplementedError("VM classes must implement this method")


    @abstractmethod
    def set_block_transactions(self, base_block, new_header, transactions, receipts):
        raise NotImplementedError("VM classes must implement this method")

    #
    # Finalization
    #
#    @abstractmethod
#    def finalize_block(self, block):
#        raise NotImplementedError("VM classes must implement this method")

    @abstractmethod
    def pack_block(self, block, *args, **kwargs):
        raise NotImplementedError("VM classes must implement this method")

    #
    # Headers
    #
    @abstractmethod
    def configure_header(self, **header_params):
        """
        Setup the current header with the provided parameters.  This can be
        used to set fields like the gas limit or timestamp to value different
        than their computed defaults.
        """
        raise NotImplementedError("VM classes must implement this method")

    @classmethod
    @abstractmethod
    def create_header_from_parent(cls, parent_header, **header_params):
        """
        Creates and initializes a new block header from the provided
        `parent_header`.
        """
        raise NotImplementedError("VM classes must implement this method")

    #
    # Blocks
    #
    @classmethod
    @abstractmethod
    def generate_block_from_parent_header_and_coinbase(cls, parent_header, coinbase):
        raise NotImplementedError("VM classes must implement this method")

    @classmethod
    @abstractmethod
    def get_block_class(cls) -> Type['BaseBlock']:
        raise NotImplementedError("VM classes must implement this method")


    @classmethod
    @abstractmethod
    def get_prev_hashes(cls, last_block_hash, chaindb):
        raise NotImplementedError("VM classes must implement this method")

    #
    # Transactions
    #
    @abstractmethod
    def create_transaction(self, *args, **kwargs):
        raise NotImplementedError("VM classes must implement this method")

    @classmethod
    @abstractmethod
    def get_transaction_class(cls):
        raise NotImplementedError("VM classes must implement this method")

    #
    # Validate
    #
    @abstractmethod
    def validate_block(self, block):
        raise NotImplementedError("VM classes must implement this method")

    @abstractmethod
    def validate_transaction_against_header(self, base_header, transaction):
        """
        Validate that the given transaction is valid to apply to the given header.

        :param base_header: header before applying the transaction
        :param transaction: the transaction to validate

        :raises: ValidationError if the transaction is not valid to apply
        """
        raise NotImplementedError("VM classes must implement this method")

    #
    # State
    #
    @classmethod
    @abstractmethod
    def get_state_class(cls):
        raise NotImplementedError("VM classes must implement this method")

    @abstractmethod
    @contextlib.contextmanager
    def state_in_temp_block(self):
        raise NotImplementedError("VM classes must implement this method")


class VM(BaseVM):
    """
    The :class:`~evm.vm.base.BaseVM` class represents the Chain rules for a
    specific protocol definition such as the Frontier or Homestead network.

      .. note::

        Each :class:`~evm.vm.base.BaseVM` class must be configured with:

        - ``block_class``: The :class:`~evm.rlp.blocks.Block` class for blocks in this VM ruleset.
        - ``_state_class``: The :class:`~evm.vm.state.State` class used by this VM for execution.
    """
    def __init__(self, header, chaindb, private_key: BaseKey, network_id):
        self.chaindb = chaindb
        self.wallet_address = chaindb.wallet_address
        self.private_key = private_key
        self.network_id = network_id
        
        # new for helios: we want to make sure the newly created block is a queueblock
        # TODO: make sure the VM doesnt need this to be a normal block under normal operations
        # When a new block is imported, it just replaces self.block with a normal block.
        # apply transactions doesnt, though. So will need to have some check there.
        # also check to make sure the code below gives the correct type of block
        if chaindb.header_exists(header.hash):
            self.block = self.get_block_class().from_header(header=header, chaindb=self.chaindb)
            if self.block.header.sender != self.wallet_address:
                raise BlockOnWrongChain("Block sender doesnt match chain wallet address")
            self.logger.debug("Initializing VM with completed block")
        else:
            self.block = self.get_queue_block_class().from_header(header=header)
            self.logger.debug("Initializing VM with queue block")
        

        self.state = self.get_state_class().from_saved_state_root(db=self.chaindb.db, execution_context=self.block.header.create_execution_context(self.previous_hashes))
        
    #
    # Logging
    #
    @property
    def logger(self):
        return logging.getLogger('evm.vm.base.VM.{0}'.format(self.__class__.__name__))

    #
    # Execution
    #
    def apply_transaction(self, header, transaction):
        """
        Apply the transaction to the current block. This is a wrapper around
        :func:`~evm.vm.state.State.apply_transaction` with some extra orchestration logic.

        :param header: header of the block before application
        :param transaction: to apply
        """

        self.validate_transaction_against_header(header, transaction)
        state_root, computation = self.state.apply_transaction(transaction)
        receipt = self.make_receipt(header, transaction, computation, self.state)
        
        
        
        new_header = header.copy(
            bloom=int(BloomFilter(header.bloom) | receipt.bloom),
            gas_used=receipt.gas_used,
        )

        return new_header, receipt, computation

    def execute_bytecode(self,
                         origin,
                         gas_price,
                         gas,
                         to,
                         sender,
                         value,
                         data,
                         code,
                         code_address=None,
                         ):
        exit("NOT IMPLEMENTED YET")
        """
        Execute raw bytecode in the context of the current state of
        the virtual machine.
        """
        if origin is None:
            origin = sender

        # Construct a message
        message = Message(
            gas=gas,
            to=to,
            sender=sender,
            value=value,
            data=data,
            code=code,
            code_address=code_address,
        )

        # Construction a tx context
        transaction_context = self.state.get_transaction_context_class()(
            gas_price=gas_price,
            origin=origin,
        )

        # Execute it in the VM
        return self.state.get_computation(message, transaction_context).apply_computation(
            self.state,
            message,
            transaction_context,
        )

    def _apply_all_transactions(self, transactions, base_header):
        receipts = []
        previous_header = base_header
        result_header = base_header

        for transaction in transactions:
            result_header, receipt, _ = self.apply_transaction(previous_header, transaction)

            previous_header = result_header
            receipts.append(receipt)

        return result_header, receipts

    #
    # Mining
    #
    def import_block(self, block, *args, **kwargs):
        """
        Import the given block to the chain.
        """
        #TODO:check to see if it is replacing a block, or being added to the top
        if not isinstance(block, self.get_queue_block_class()):
            if block.sender != self.wallet_address:
                raise BlockOnWrongChain("Tried to import a block that doesnt belong on this chain.")
            
        #TODO: if importing queueblock, verify it here first before trying to import.
        self.block = self.block.copy(
            header=self.configure_header(
                gas_limit=block.header.gas_limit,
                timestamp=block.header.timestamp,
                extra_data=block.header.extra_data,
                v=block.header.v,
                r=block.header.r,
                s=block.header.s,
            )
        )
        # we need to re-initialize the `state` to update the execution context.
        self.state = self.get_state_class().from_saved_state_root(
                db=self.chaindb.db, 
                execution_context=self.block.header.create_execution_context(self.previous_hashes)
                )
        
        
        #run all of the transactions.
        last_header, receipts = self._apply_all_transactions(block.transactions, self.block.header)
        
        
        #then run all receive transactions
        last_header, receive_receipts = self._apply_all_transactions(block.receive_transactions, last_header)
        
        #then combine
        receipts.extend(receive_receipts)
        
        self.block = self.set_block_transactions(
            self.block,
            last_header,
            block.transactions,
            receipts,
        )
         
        self.block = self.set_block_receive_transactions(
            self.block,
            self.block.header,
            block.receive_transactions
        )
        
        
        #need to save the closing balance into the block.
        #self.block = self.save_closing_balance(self.block)
        self.block = self.save_account_hash(self.block)
        
        #TODO: find out if this packing is nessisary
        packed_block = self.pack_block(self.block, *args, **kwargs)
        
        if isinstance(packed_block, self.get_queue_block_class()):
            """
            If it is a queueblock, then it must be signed now.
            It cannot be signed earlier because the header fields were changing
            """
            #update timestamp now.
            self.logger.debug("setting timestamp of block to {}".format(int(time.time())))
            packed_block = packed_block.copy(
                header=packed_block.header.copy(
                    timestamp=int(time.time())
                ),
            )
            if self.private_key is None:
                raise ValueError("Cannot sign block because no private key given")
            self.logger.debug("signing block")
            packed_block = packed_block.as_complete_block(self.private_key, self.network_id)
            
        # Perform validation
        self.validate_block(packed_block)
        
        
        
        #save all send transactions in the state as receivable
        self.save_transactions_as_receivable(self.block.header, self.block.transactions)
        
        self.state.account_db.persist(save_state_root=True)
        
        return packed_block

    def save_transaction_as_receivable(self,block_header, transaction):
        self.state.account_db.add_receivable_transaction(transaction.to, transaction.hash, block_header.hash)
        
    def save_transactions_as_receivable(self,block_header, transactions):
        for transaction in transactions:
            self.save_transaction_as_receivable(block_header, transaction)
        

    def set_block_transactions(self, base_block, new_header, transactions, receipts):
       
        tx_root_hash, tx_kv_nodes = make_trie_root_and_nodes(transactions)
        self.chaindb.persist_trie_data_dict(tx_kv_nodes)

        receipt_root_hash, receipt_kv_nodes = make_trie_root_and_nodes(receipts)
        self.chaindb.persist_trie_data_dict(receipt_kv_nodes)
        
        return base_block.copy(
            transactions=transactions,
            header=new_header.copy(
                transaction_root=tx_root_hash,
                receipt_root=receipt_root_hash,
            ),
        )
            
    def set_block_receive_transactions(self, base_block, new_header, transactions):

        tx_root_hash, tx_kv_nodes = make_trie_root_and_nodes(transactions)
        self.chaindb.persist_trie_data_dict(tx_kv_nodes)

        return base_block.copy(
            receive_transactions=transactions,
            header=new_header.copy(
                receive_transaction_root=tx_root_hash
            ),
        )

    #
    # Finalization
    #
    def save_closing_balance(self, block):
        closing_balance = self.state.account_db.get_balance(self.wallet_address)
        
        return block.copy(
            header=block.header.copy(
                closing_balance = closing_balance
            ),
        )
            
    def save_account_hash(self, block):
        account_hash = self.state.account_db.get_account_hash(self.wallet_address)
        return block.copy(
            header=block.header.copy(
                account_hash = account_hash
            ),
        )
        
    def pack_block(self, block, *args, **kwargs):
        """
        Pack block for mining.

        :param bytes coinbase: 20-byte public address to receive block reward
        :param bytes uncles_hash: 32 bytes
        :param bytes state_root: 32 bytes
        :param bytes transaction_root: 32 bytes
        :param bytes receipt_root: 32 bytes
        :param int bloom:
        :param int gas_used:
        :param bytes extra_data: 32 bytes
        :param bytes mix_hash: 32 bytes
        :param bytes nonce: 8 bytes
        """

        provided_fields = set(kwargs.keys())
        known_fields = set(BlockHeader._meta.field_names)
        unknown_fields = provided_fields.difference(known_fields)

        if unknown_fields:
            raise AttributeError(
                "Unable to set the field(s) {0} on the `BlockHeader` class. "
                "Received the following unexpected fields: {1}.".format(
                    ", ".join(known_fields),
                    ", ".join(unknown_fields),
                )
            )

        header = block.header.copy(**kwargs)
        packed_block = block.copy(header=header)

        return packed_block

    #
    # Blocks
    #
    @classmethod
    def generate_block_from_parent_header_and_coinbase(cls, parent_header, coinbase):
        """
        Generate block from parent header and coinbase.
        """
        block_header = generate_header_from_parent_header(
            cls.compute_difficulty,
            parent_header,
            coinbase,
            timestamp=parent_header.timestamp + 1,
        )
        block = cls.get_block_class()(
            block_header,
            transactions=[],
            uncles=[],
        )
        return block

    @classmethod
    def get_block_class(cls) -> Type['BaseBlock']:
        """
        Return the :class:`~evm.rlp.blocks.Block` class that this VM uses for blocks.
        """
        if cls.block_class is None:
            raise AttributeError("No `block_class` has been set for this VM")
        else:
            return cls.block_class

    @classmethod
    def get_queue_block_class(cls) -> Type['BaseQueueBlock']:
        """
        Return the :class:`~evm.rlp.blocks.Block` class that this VM uses for queue blocks.
        """
        if cls.queue_block_class is None:
            raise AttributeError("No `queue_block_class` has been set for this VM")
        else:
            return cls.queue_block_class
    
    @classmethod    
    def create_genesis_block(cls):
        block = cls.get_queue_block_class()
        genesis_block = block.make_genesis_block()
        return genesis_block
    
    @classmethod
    @functools.lru_cache(maxsize=32)
    @to_tuple
    def get_prev_hashes(cls, last_block_hash, chaindb):
        if last_block_hash == GENESIS_PARENT_HASH:
            return

        block_header = get_block_header_by_hash(last_block_hash, chaindb)

        for _ in range(MAX_PREV_HEADER_DEPTH):
            yield block_header.hash
            try:
                block_header = get_parent_header(block_header, chaindb)
            except (IndexError, HeaderNotFound):
                break

    @property
    def previous_hashes(self):
        """
        Convenience API for accessing the previous 255 block hashes.
        """
        return self.get_prev_hashes(self.block.header.parent_hash, self.chaindb)
    
    
        
    #
    # Transactions
    #
    def create_transaction(self, *args, **kwargs):
        """
        Proxy for instantiating a signed transaction for this VM.
        """
        return self.get_transaction_class()(*args, **kwargs)
    
    def create_receive_transaction(self, *args, **kwargs):
        """
        Proxy for instantiating a signed transaction for this VM.
        """
        return self.get_receive_transaction_class()(*args, **kwargs)
            
        
        
    @classmethod
    def get_transaction_class(cls):
        """
        Return the class that this VM uses for transactions.
        """
        return cls.get_block_class().get_transaction_class()
    
    @classmethod
    def get_receive_transaction_class(cls):
        """
        Return the class that this VM uses for transactions.
        """
        return cls.get_block_class().get_receive_transaction_class()

    #
    # Validate
    #
    def check_wait_before_new_block(self, block):
        parent_header = get_parent_header(block.header, self.chaindb)
        parent_time = parent_header.timestamp
        difference = int(time.time())-parent_time
        time_left = MIN_TIME_BETWEEN_BLOCKS - difference
        return time_left
        
    def validate_block(self, block):
        """
        Validate the the given block.
        """
        if not (isinstance(block, self.get_block_class()) or isinstance(block, self.get_queue_block_class())):
            raise ValidationError(
                "This vm ({0!r}) is not equipped to validate a block of type {1!r}".format(
                    self,
                    block,
                )
            )
        if not block.is_genesis:
            #check signature validity. this will raise a validation error
            block.header.check_signature_validity()

            parent_header = get_parent_header(block.header, self.chaindb)

            validate_gas_limit(block.header.gas_limit, parent_header.gas_limit)
            validate_length_lte(block.header.extra_data, 32, title="BlockHeader.extra_data")
            
            # timestamp
            if block.header.timestamp < parent_header.timestamp:
                raise ValidationError(
                    "`timestamp` is before the parent block's timestamp.\n"
                    "- block  : {0}\n"
                    "- parent : {1}. ".format(
                        block.header.timestamp,
                        parent_header.timestamp,
                    )
                )
            elif block.header.timestamp == parent_header.timestamp:
                raise ValidationError(
                    "`timestamp` is equal to the parent block's timestamp\n"
                    "- block : {0}\n"
                    "- parent: {1}.\n"
                    "- current timestamp : {2}".format(
                        block.header.timestamp,
                        parent_header.timestamp,
                        time.time()
                    )
                )

        tx_root_hash, _ = make_trie_root_and_nodes(block.transactions)
        if tx_root_hash != block.header.transaction_root:
            raise ValidationError(
                "Block's transaction_root ({0}) does not match expected value: {1}".format(
                    block.header.transaction_root, tx_root_hash))
        re_tx_root_hash, _ = make_trie_root_and_nodes(block.receive_transactions)
        if re_tx_root_hash != block.header.receive_transaction_root:
            raise ValidationError(
                "Block's receive transaction_root ({0}) does not match expected value: {1}".format(
                    block.header.receive_transaction_root, re_tx_root_hash))

    #
    # State
    #
    @classmethod
    def get_state_class(cls):
        """
        Return the class that this VM uses for states.
        """
        if cls._state_class is None:
            raise AttributeError("No `_state_class` has been set for this VM")

        return cls._state_class
    
        
    @contextlib.contextmanager
    def state_in_temp_block(self):
        header = self.block.header
        temp_block = self.generate_block_from_parent_header_and_coinbase(header, header.coinbase)
        prev_hashes = (header.hash, ) + self.previous_hashes

        state = self.get_state_class()(
            db=self.chaindb.db,
            execution_context=temp_block.header.create_execution_context(prev_hashes),
            state_root=temp_block.header.state_root,
        )

        snapshot = state.snapshot()
        yield state
        state.revert(snapshot)
