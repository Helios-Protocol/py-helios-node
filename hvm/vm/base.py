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
    Tuple,
    Optional,
    Union,
)

import time

import rlp_cython as rlp

from eth_bloom import (
    BloomFilter,
)

from eth_utils import (
    to_tuple,
    encode_hex,
    to_int
)

from eth_hash.auto import keccak

from hvm.constants import (
    GENESIS_PARENT_HASH,
    MAX_PREV_HEADER_DEPTH,
    MAX_UNCLES,
    MIN_TIME_BETWEEN_BLOCKS,
    ZERO_HASH32,
    BLANK_REWARD_HASH)
from hvm.db.trie import make_trie_root_and_nodes
from hvm.db.chain import BaseChainDB  # noqa: F401
from hvm.exceptions import (
    HeaderNotFound,
    ValidationError,
    IncorrectBlockType,
    IncorrectBlockHeaderType,
    BlockOnWrongChain,
    ParentNotFound,
    ReceivableTransactionNotFound,
    TransactionNotFound)
from hvm.rlp.blocks import (  # noqa: F401
    BaseBlock,
    BaseQueueBlock,
)
from hvm.rlp.transactions import (  # noqa: F401
    BaseTransaction,
    BaseReceiveTransaction
)
from hvm.rlp.headers import (
    BlockHeader,
    BaseBlockHeader)
from hvm.rlp.receipts import Receipt  # noqa: F401
from hvm.utils.datatypes import (
    Configurable,
)
from hvm.utils.db import (
    get_parent_header,
    get_block_header_by_hash,
)
from hvm.validation import (
    validate_length_lte,
    validate_gas_limit,
    validate_private_key,
)
from hvm.vm.message import (
    Message,
)
from hvm.vm.state import BaseState  # noqa: F401
from eth_typing import (
    Hash32,
    Address,
)
from eth_keys.datatypes import(
        BaseKey,
        PublicKey,
        PrivateKey
)
from hvm.utils.rlp import convert_rlp_to_correct_class
from hvm.rlp.consensus import StakeRewardBundle
from hvm.db.consensus import ConsensusDB
from hvm.types import Timestamp

from hvm.vm.computation import BaseComputation

class BaseVM(Configurable, metaclass=ABCMeta):
    block_class: Type[BaseBlock] = None
    queue_block_class: Type[BaseQueueBlock] = None
    fork: str = None
    chaindb: BaseChainDB = None
    _state_class: Type[BaseState] = None
    network_id: int = 0
    state: BaseState = None
    block: BaseBlock = None
    queue_block: BaseQueueBlock = None

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
    def apply_send_transaction(self,
                            header: BlockHeader,
                            transaction: BaseTransaction,
                            caller_chain_address: Address,
                            validate: bool = True) -> Tuple[BlockHeader, Receipt, BaseComputation]:
        raise NotImplementedError("VM classes must implement this method")

    @abstractmethod
    def apply_receive_transaction(self,
                               header: BlockHeader,
                               receive_transaction: BaseReceiveTransaction,
                               caller_chain_address: Address,
                               validate: bool = True) -> Tuple[Optional[BlockHeader],
                                                               Optional[Receipt],
                                                               BaseComputation,
                                                               Optional[BaseReceiveTransaction]]:
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
    def make_receipt(self, base_header: BaseBlockHeader,
                            computation: BaseComputation,
                            send_transaction: BaseTransaction,
                            receive_transaction: BaseReceiveTransaction = None,
                            refund_transaction: BaseReceiveTransaction = None,
                            ) -> Receipt:
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
    def get_block_class(cls) -> Type['BaseBlock']:
        raise NotImplementedError("VM classes must implement this method")


    @classmethod
    @abstractmethod
    def get_prev_hashes(cls, last_block_hash, chaindb):
        raise NotImplementedError("VM classes must implement this method")

    @classmethod
    @abstractmethod
    def convert_block_to_correct_class(self, block: BaseBlock) -> BaseBlock:
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

    @classmethod
    @abstractmethod
    def get_receive_transaction_class(cls):
        raise NotImplementedError("VM classes must implement this method")

    @abstractmethod
    def save_recievable_transactions(self, block_header_hash: Hash32, computations: List[BaseComputation]) -> None:
        raise NotImplementedError("VM classes must implement this method")


    #
    # Validate
    #
    @abstractmethod
    def validate_block(self, block):
        raise NotImplementedError("VM classes must implement this method")

    @abstractmethod
    def validate_transaction_against_header(self, base_header, send_transaction, receive_transaction):
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



class VM(BaseVM):
    """
    The :class:`~hvm.vm.base.BaseVM` class represents the Chain rules for a
    specific protocol definition such as the Frontier or Homestead network.

      .. note::

        Each :class:`~hvm.vm.base.BaseVM` class must be configured with:

        - ``block_class``: The :class:`~hvm.rlp_templates.blocks.Block` class for blocks in this VM ruleset.
        - ``_state_class``: The :class:`~hvm.vm.state.State` class used by this VM for execution.
    """
    header: BlockHeader = None
    _block: BaseBlock = None
    _queue_block: BaseQueueBlock = None
    _state: BaseState = None

    def __init__(self, header:BlockHeader, chaindb: BaseChainDB, consensus_db: ConsensusDB, wallet_address:Address, private_key: BaseKey, network_id: int):
        self.chaindb = chaindb
        self.consensus_db = consensus_db
        self.wallet_address = wallet_address
        self.private_key = private_key
        self.network_id = network_id
        self.header = header

        if self.header.chain_address != self.wallet_address:
            raise BlockOnWrongChain("Header chain address doesnt match chain wallet address. wallet_address = {}, chain_address in block header= {}".format(encode_hex(self.wallet_address), encode_hex(self.header.chain_address)))


    #
    # Logging
    #
    @property
    def logger(self):
        return logging.getLogger('hvm.vm.base.VM.{0}'.format(self.__class__.__name__))

    @property
    def block(self) -> BaseBlock:
        if self._block is None:
            self._block = self.get_block_class().from_header(header=self.header, chaindb=self.chaindb)
        return self._block

    @block.setter
    def block(self, val):
        self._block = val

    @property
    def queue_block(self) -> BaseQueueBlock:
        if self._queue_block is None:
            self._queue_block = self.get_queue_block_class().from_header(header=self.header)
        return self._queue_block

    @queue_block.setter
    def queue_block(self, val):
        self._queue_block = val


    @property
    def state(self) -> BaseState:
        if self._state is None:
            self._state = self.get_state_class()(db=self.chaindb.db, execution_context=self.header.create_execution_context(self.previous_hashes))
        return self._state

    @state.setter
    def state(self, val):
        self._state = val

    #
    # Execution
    #
    def apply_send_transaction(self,
                               header: BlockHeader,
                               transaction: BaseTransaction,
                               caller_chain_address: Address,
                               validate: bool = True) -> Tuple[BlockHeader, Receipt, BaseComputation]:
        """
        Apply the transaction to the current block. This is a wrapper around
        :func:`~hvm.vm.state.State.apply_transaction` with some extra orchestration logic.

        :param header: header of the block before application
        :param transaction: to apply
        """
        #caller_chain_address = header.sender
        #this is a send transaction
        send_transaction = transaction
        receive_transaction = None
        if validate:
            self.validate_transaction_against_header(header, send_transaction=send_transaction)


        computation, _ = self.state.apply_transaction(send_transaction = send_transaction,
                                                   caller_chain_address = caller_chain_address,
                                                   receive_transaction = receive_transaction,
                                                   validate = validate)
        if validate:
            receipt = self.make_receipt(header, computation, send_transaction)
            
            new_header = header.copy(
                bloom=int(BloomFilter(header.bloom) | receipt.bloom),
                gas_used=receipt.gas_used,
            )
    
            return new_header, receipt, computation
        else:
            return None, None, computation


    def apply_receive_transaction(self,
                               header: BlockHeader,
                               receive_transaction: BaseReceiveTransaction,
                               caller_chain_address: Address,
                               validate: bool = True) -> Tuple[Optional[BlockHeader],
                                                               Optional[Receipt],
                                                               BaseComputation,
                                                               Optional[BaseReceiveTransaction]]:
        """
        Apply the transaction to the current block. This is a wrapper around
        :func:`~hvm.vm.state.State.apply_transaction` with some extra orchestration logic.

        :param header: header of the block before application
        :param transaction: to apply
        """
        # Lets make sure we have this receivable transaction in the account
        receivable_tx_key = self.state.account_db.get_receivable_transaction(caller_chain_address,
                                                                             receive_transaction.send_transaction_hash)

        if receivable_tx_key is None:
            # There is no receivable transaction that matches this one.
            # now check to see if the block is in the canonical chain, but didnt have the transaction in it
            try:
                block_hash, index, is_receive = self.chaindb.get_transaction_index(receive_transaction.send_transaction_hash)
                if block_hash == receive_transaction.sender_block_hash:
                    raise ValidationError(
                        'Receive transaction is invalid. We do have the send transaction and send block, but it has already been received.')
                else:
                    raise ValidationError(
                        'Receive transaction is invalid. We have already imported this transaction, but it was from another block.')
            except TransactionNotFound:
                if self.chaindb.is_in_canonical_chain(receive_transaction.sender_block_hash):
                    raise ValidationError(
                        'Receive transaction is invalid. We have the sender block, but it didn\'t contain the send transaction')

            if self.chaindb.exists(receive_transaction.send_transaction_hash):
                self.logger.debug("The missing receivable transaction exists in the db but not canonical chain.")

            if self.chaindb.is_in_canonical_chain(receive_transaction.sender_block_hash):
                self.logger.debug("The sender block of the missing receivable transaction is in the canonical chain. This must means the tx is in there, but wasnt saved to canonical transactions...")

            raise ReceivableTransactionNotFound("caller_chain_address = {}, send_transaction_hash = {}, sender_block_hash = {}".format(
                encode_hex(caller_chain_address),
                encode_hex(receive_transaction.send_transaction_hash),
                encode_hex(receive_transaction.sender_block_hash),
            ))

        else:
            #now lets get all of the relevant transactions in this chain
            try:

                if receive_transaction.is_refund:
                    #this is a refund transaction. We need to load the receive_transaction containing the refund and the send_transaction
                    refund_transaction = receive_transaction

                    block_hash, index, is_receive = self.chaindb.get_transaction_index(refund_transaction.send_transaction_hash)

                    if block_hash != refund_transaction.sender_block_hash:
                        raise ValidationError("The sender_block_hash of this refund transaction doesn't match the block of the receive transaction")

                    if not is_receive:
                        raise ValidationError("This refund transaction references a send transaction. This is not allowed.")

                    receive_transaction = self.chaindb.get_receive_transaction_by_index_and_block_hash(
                        block_hash,
                        index,
                        self.get_receive_transaction_class(),
                    )
                else:
                    refund_transaction = None



                block_hash, index, is_receive = self.chaindb.get_transaction_index(receive_transaction.send_transaction_hash)

                if block_hash != receive_transaction.sender_block_hash:
                    raise ValidationError(
                        "The sender_block_hash of this receive transaction doesn't match the block of the send transaction")

                if is_receive:
                    raise ValidationError(
                        "This receive transaction references another receive transaction. This is not allowed.")

                send_transaction = self.chaindb.get_transaction_by_index_and_block_hash(
                    block_hash,
                    index,
                    self.get_transaction_class(),
                )

            except TransactionNotFound:
                raise ReceivableTransactionNotFound()



            # we assume past this point that, if it is a receive transaction, the send transaction exists in account
            computation, processed_transaction = self.state.apply_transaction(send_transaction=send_transaction,
                                                       caller_chain_address=caller_chain_address,
                                                       receive_transaction=receive_transaction,
                                                       refund_transaction=refund_transaction,
                                                       validate=validate)

            if validate:
                receipt = self.make_receipt(header, computation, send_transaction, receive_transaction, refund_transaction)

                new_header = header.copy(
                    bloom=int(BloomFilter(header.bloom) | receipt.bloom),
                    gas_used=receipt.gas_used,
                )

                return new_header, receipt, computation, processed_transaction
            else:
                return None, None, computation, processed_transaction

    def _apply_reward_bundle(self, reward_bundle: StakeRewardBundle, block_timestamp: Timestamp, wallet_address: Address = None, validate = True) -> None:

        if wallet_address is None:
            wallet_address = self.wallet_address

        if validate:
            self.consensus_db.validate_reward_bundle(reward_bundle, chain_address=wallet_address, block_timestamp = block_timestamp)

        self.state.apply_reward_bundle(reward_bundle, wallet_address)




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


    def _apply_all_send_transactions(self, transactions, base_header, caller_chain_address, validate = True):
        receipts = []
        previous_header = base_header
        result_header = base_header
        computations = []

        if validate:
            for transaction in transactions:
                result_header, receipt, computation = self.apply_send_transaction(previous_header, transaction, caller_chain_address, validate = validate)

                previous_header = result_header
                receipts.append(receipt)
                computations.append(computation)
    
            return result_header, receipts, computations
        else:
            for transaction in transactions:
                result_header, receipt, computation = self.apply_send_transaction(previous_header, transaction, validate = validate)
                computations.append(computation)
            return result_header, [], computations

    def _apply_all_receive_transactions(self, transactions, base_header, caller_chain_address, validate=True):
        receipts = []
        previous_header = base_header
        result_header = base_header
        computations = []
        processed_receive_transactions = []

        if validate:
            for transaction in transactions:
                result_header, receipt, computation, processed_receive_tx = self.apply_receive_transaction(previous_header, transaction,
                                                                                  caller_chain_address,
                                                                                  validate=validate)

                previous_header = result_header
                receipts.append(receipt)
                computations.append(computation)
                processed_receive_transactions.append(processed_receive_tx)

            return result_header, receipts, computations, processed_receive_transactions
        else:
            for transaction in transactions:
                result_header, receipt, computation, processed_receive_tx = self.apply_receive_transaction(previous_header, transaction,
                                                                                  validate=validate)
                computations.append(computation)
                processed_receive_transactions.append(processed_receive_tx)
            return result_header, [], computations, processed_receive_transactions

    def refresh_state(self):
        self.state = self.get_state_class()(
                db=self.chaindb.db, 
                execution_context=self.block.header.create_execution_context(self.previous_hashes)
                )

    def reverse_pending_transactions(self, block_header):
        """
        Doesnt actually reverse transactions. It just re-adds the received transactions as receivable, 
        and removes all send transactions as receivable from the receiver state
        """

        wallet_address = block_header.sender
        send_transactions = self.chaindb.get_block_transactions(block_header, self.get_block_class().transaction_class)
        receive_transactions = self.chaindb.get_block_receive_transactions(block_header, self.get_block_class().receive_transaction_class)

        self.delete_transactions_as_receivable(send_transactions, receive_transactions)

        for receive_transaction in receive_transactions:
            #only add this back if the sender block has still been processed
            #need to verify that this block is in the canonical chain
            if self.chaindb.is_in_canonical_chain(receive_transaction.sender_block_hash):
                try:
                    self.state.account_db.add_receivable_transaction(wallet_address, receive_transaction.send_transaction_hash,
                                                                     receive_transaction.sender_block_hash)
                    #self.save_transaction_as_receivable(receive_transaction.sender_block_hash, receive_transaction.transaction)
                except ValueError:
                    pass
                
                
    #
    # Mining
    #

    def import_block(self, block: Union[BaseBlock, BaseQueueBlock], validate = True, **kwargs):
        """
        Import the given block to the chain.
        """

        if isinstance(block, self.get_queue_block_class()):
            is_queue_block = True
            head_block = self.queue_block
            block_timestamp = int(time.time())
            # Replace the head block with a queueblock

        else:
            is_queue_block = False
            head_block = self.block
            block_timestamp = block.header.timestamp
            if (block.sender != self.wallet_address and not (
                self.state.account_db.account_has_code(block.header.chain_address) or
                self.state.account_db.has_pending_smart_contract_transactions(block.header.chain_address))):
                raise BlockOnWrongChain("Tried to import a block that doesnt belong on this chain.")

        # Base the block off of the existing head block so that parameters are correct. Then after importing we will
        # check to make sure the block is unchanged to catch any invalid parameters of the original block.
        block = head_block.copy(
            header=self.configure_header(
                gas_limit=block.header.gas_limit,
                gas_used=0,
                timestamp=block.header.timestamp,
                extra_data=block.header.extra_data,
                v=block.header.v,
                r=block.header.r,
                s=block.header.s,
            ),
            transactions = block.transactions,
            receive_transactions = block.receive_transactions,
            reward_bundle = block.reward_bundle
        )


        # we need to re-initialize the `state` to update the execution context.
        #this also removes and unpersisted state changes.
        self.refresh_state()
        
        #run all of the transactions.
        last_header, receipts, send_computations = self._apply_all_send_transactions(block.transactions, block.header, self.wallet_address)
        
        
        #then run all receive transactions
        last_header, receive_receipts, receive_computations, processed_receive_transactions = self._apply_all_receive_transactions(block.receive_transactions, last_header, self.wallet_address)

        if not (block.reward_bundle.reward_type_1.amount == 0 and block.reward_bundle.reward_type_2.amount == 0):
            self._apply_reward_bundle(block.reward_bundle, block_timestamp, self.wallet_address, validate=validate)


        #then combine
        receipts.extend(receive_receipts)
        
        block = self.set_block_transactions(
            block,
            last_header,
            block.transactions,
            receipts,
        )

        block = self.set_block_receive_transactions(
            block,
            block.header,
            processed_receive_transactions
        )

        block = self.set_block_reward_hash(
            block,
            block.header,
            block.reward_bundle
        )



        
        block = self.save_account_hash(block)

        account_balance = self.state.account_db.get_balance(self.wallet_address)
        self.logger.debug("setting account_balance of block to {}".format(account_balance))
        block = block.copy(
            header=block.header.copy(
                account_balance=account_balance,
            ),
        )

        
        if is_queue_block:
            """
            If it is a queueblock, then it must be signed now.
            It cannot be signed earlier because the header fields were changing
            """
            #update timestamp now.
            self.logger.debug("setting timestamp of block to {}".format(int(time.time())))
            block = block.copy(
                header=block.header.copy(
                    timestamp=block_timestamp,
                ),
            )

            # change any final header parameters before signing
            block = self.pack_block(block, **kwargs)


            if self.private_key is None:
                raise ValueError("Cannot sign block because no private key given")
            self.logger.debug("signing block")
            block = block.as_complete_block(self.private_key, self.network_id)
            

        #save all send transactions in the state as receivable
        #we have to do this at the end here because the block hash is still changing when transactions are being processed.
        self.save_recievable_transactions(block.header.hash, send_computations, processed_receive_transactions)

        if validate:
            # Perform validation
            self.validate_block(block)
        
        #state is persisted from chain after ensuring block unchanged

        return block


    #this can be used for fast sync
    #dangerous. It assumes all blocks are correct.
    def import_block_no_verification(self, block, *args, **kwargs):
        """
        Import the given block to the chain.
        """
        #TODO:check to see if it is replacing a block, or being added to the top
        #TODO: allow this for contract addresses
        if block.sender != self.wallet_address:
            raise BlockOnWrongChain("Tried to import a block that doesnt belong on this chain.")
            

        # we need to re-initialize the `state` to update the execution context.
        self.refresh_state()
        
        #if we don't validate here, then we are opening ourselves up to someone having invalid receive transactions.
        #We would also not check to see if the send transaction exists. So lets validate for now. We can only 
        #set validate to False if we 100% trust the source
        #run all of the transactions.
        #self._apply_all_transactions(block.transactions, block.header, validate = False)
        self._apply_all_transactions(block.transactions, block.header, validate = True)
        
        #then run all receive transactions
        #self._apply_all_transactions(block.receive_transactions, block.header, validate = False)
        self._apply_all_transactions(block.receive_transactions, block.header, validate = True)

        #save all send transactions in the state as receivable
        self.save_transactions_as_receivable(block.header.hash, block.transactions)
        
        self.state.account_db.persist()
        
        return block


    def save_recievable_transactions(self,block_header_hash: Hash32, computations: List[BaseComputation], receive_transactions: List[BaseReceiveTransaction]) -> None:
        '''
        Saves send transactions as receivable. This requires the computations to cover transactions that deploy a contract to a new storage address.
        In that case, we need the computation to know what the storage address is.
        This also saves any receive transactions containing a refund as receivable.
        :param block_header_hash:
        :param computations:
        :param receive_transactions:
        :return:
        '''
        for computation in computations:
            msg = computation.msg
            transaction_context = computation.transaction_context
            self.state.account_db.add_receivable_transaction(msg.storage_address,
                                                             transaction_context.send_tx_hash,
                                                             block_header_hash,
                                                             msg.is_create)

        for receive_transaction in receive_transactions:
            if not receive_transaction.is_refund and receive_transaction.remaining_refund != 0:
                sender_chain_address = self.chaindb.get_chain_wallet_address_for_block_hash(receive_transaction.sender_block_hash)
                self.state.account_db.add_receivable_transaction(sender_chain_address,
                                                                 receive_transaction.hash,
                                                                 block_header_hash)

            
    def delete_transaction_as_receivable(self, wallet_address, transaction_hash):
        try:
            self.state.account_db.delete_receivable_transaction(wallet_address, transaction_hash)
        except ReceivableTransactionNotFound:
            pass
        
    def delete_transactions_as_receivable(self,transactions, receive_transactions):
        for transaction in transactions:
            self.delete_transaction_as_receivable(transaction.to, transaction.hash)

        for receive_transaction in receive_transactions:
            if not receive_transaction.is_refund and receive_transaction.remaining_refund != 0:
                # receive transactions that have refund remaining will have saved the refund as receivable. Need to
                # delete those too.
                # The refund gets sent back to the sender. So lets find the sender chain, and remove it from there.
                sender_header = self.chaindb.get_block_header_by_hash(receive_transaction.sender_block_hash)
                sender_wallet_address = sender_header.chain_address
                self.delete_transaction_as_receivable(sender_wallet_address, receive_transaction.hash)
        
    def save_items_to_db_as_trie(self, items, root_hash_to_verify = None):
        root_hash, kv_nodes = make_trie_root_and_nodes(items)
        if root_hash_to_verify is not None:
            if root_hash != root_hash_to_verify:
                raise ValidationError("root hash is not what it is expected to be.")
                
        self.chaindb.persist_trie_data_dict(kv_nodes)
        return root_hash, kv_nodes


    def set_block_reward_hash(self, block: BaseBlock, header:BlockHeader, reward_bundle: StakeRewardBundle) -> BaseBlock:
        if reward_bundle is None:
            reward_hash = BLANK_REWARD_HASH
        else:
            reward_hash = reward_bundle.hash

        return block.copy(
            reward_bundle=reward_bundle,
            header=header.copy(
                reward_hash=reward_hash
            ),
        )


    def set_block_transactions(self, base_block, new_header, transactions, receipts):
        tx_root_hash, tx_kv_nodes = self.save_items_to_db_as_trie(transactions)
        receipt_root_hash, receipt_kv_nodes = self.save_items_to_db_as_trie(receipts)

        
        return base_block.copy(
            transactions=transactions,
            header=new_header.copy(
                transaction_root=tx_root_hash,
                receipt_root=receipt_root_hash,
            ),
        )
            
    
            
    def set_block_receive_transactions(self, base_block, new_header, transactions):
        tx_root_hash, tx_kv_nodes = self.save_items_to_db_as_trie(transactions)
#        tx_root_hash, tx_kv_nodes = make_trie_root_and_nodes(transactions)
#        self.chaindb.persist_trie_data_dict(tx_kv_nodes)

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
        
    def pack_block(self, block, **kwargs):
        """
        Pack block for mining.

        :param bytes coinbase: 20-byte public address to receive block reward
        :param bytes uncles_hash: 32 bytes
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
    def get_block_class(cls) -> Type['BaseBlock']:
        """
        Return the :class:`~hvm.rlp_templates.blocks.Block` class that this VM uses for blocks.
        """
        if cls.block_class is None:
            raise AttributeError("No `block_class` has been set for this VM")
        else:
            return cls.block_class

    
    @classmethod
    def get_queue_block_class(cls) -> Type['BaseQueueBlock']:
        """
        Return the :class:`~hvm.rlp_templates.blocks.Block` class that this VM uses for queue blocks.
        """
        if cls.queue_block_class is None:
            raise AttributeError("No `queue_block_class` has been set for this VM")
        else:
            return cls.queue_block_class
        
    def convert_block_to_correct_class(self, block: BaseBlock) -> BaseBlock:
        """
        Returns a block that is an instance of the correct block class for this vm
        Also converts the send transactions, and receive transactions into the correct class.
        """
        #parameters = list(dict(sender_block_1_imported._meta.fields).values())
        correct_transactions = []
        for transaction in block.transactions:
            new_transaction = convert_rlp_to_correct_class(self.block.transaction_class, transaction)
            correct_transactions.append(new_transaction)
            
        correct_receive_transactions = []
        for receive_transaction in block.receive_transactions:
            #send_transaction = convert_rlp_to_correct_class(self.block.transaction_class, receive_transaction.transaction)
            new_receive_transaction = convert_rlp_to_correct_class(self.block.receive_transaction_class, receive_transaction)
            #new_receive_transaction = new_receive_transaction.copy(transaction = send_transaction)
            correct_receive_transactions.append(new_receive_transaction)


        new_reward_bundle = convert_rlp_to_correct_class(self.block.reward_bundle_class, block.reward_bundle)

        self.block = self.get_block_class()(
            header=block.header,
            transactions = correct_transactions,
            receive_transactions = correct_receive_transactions,
            reward_bundle = new_reward_bundle
        )

        
        return self.block

    
    @classmethod
    def create_genesis_block(cls, chain_address: Address):
        block = cls.get_queue_block_class()
        genesis_block = block.make_genesis_block(chain_address)
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
#        from hvm.rlp_templates.transactions import BaseTransaction
#        class P2PSendTransaction(rlp_templates.Serializable):
#            fields = BaseTransaction._meta.fields
            
        return self.get_transaction_class()(*args, **kwargs)
        #return P2PSendTransaction(*args, **kwargs)
    
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
        #check signature validity. this will raise a validation error
        block.header.check_signature_validity()
        
        if not block.is_genesis:
            
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
            elif (block.header.timestamp - parent_header.timestamp) < MIN_TIME_BETWEEN_BLOCKS:
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

        if block.reward_bundle is None:
            reward_bundle_hash = BLANK_REWARD_HASH
        else:
            reward_bundle_hash = block.reward_bundle.hash

        if reward_bundle_hash != block.header.reward_hash:
            raise ValidationError(
                "Block's reward hash ({0}) does not match expected value: {1}".format(
                    encode_hex(block.header.reward_hash), encode_hex(reward_bundle_hash)))


        # check that the block header balance is correct
        actual_balance = self.state.account_db.get_balance(block.header.chain_address)
        if block.header.account_balance != actual_balance:
            raise ValidationError("Block header balance is incorrect. Got {}, expected {}. Chain address = {}".format(block.header.account_balance, actual_balance, block.header.chain_address))

    #
    # State
    #
    @classmethod
    def get_state_class(cls) -> Type[BaseState]:
        """
        Return the class that this VM uses for states.
        """
        if cls._state_class is None:
            raise AttributeError("No `_state_class` has been set for this VM")

        return cls._state_class
    
        
