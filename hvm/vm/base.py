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

from hvm.utils.address import (
    generate_contract_address,
)

from hvm.constants import CREATE_CONTRACT_ADDRESS, BLOCK_GAS_LIMIT, BLOCK_TRANSACTION_LIMIT
import time

import rlp_cython as rlp

from eth_bloom import (
    BloomFilter,
)
from hvm.utils.spoof import (
    SpoofTransaction,
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
    TransactionNotFound, RequiresCodeFromMissingChain, RequiresCodeFromChainInFuture, RewardAmountRoundsToZero)
from hvm.rlp.blocks import (  # noqa: F401
    BaseBlock,
    BaseQueueBlock,
    BaseMicroBlock)
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
    micro_block_class: Type[BaseMicroBlock] = None
    block_class: Type[BaseBlock] = None
    queue_block_class: Type[BaseQueueBlock] = None
    consensus_db_class: Type[ConsensusDB] = None

    fork: str = None
    chaindb: BaseChainDB = None
    consensus_db: ConsensusDB = None
    _state_class: Type[BaseState] = None

    state: BaseState = None
    block: BaseBlock = None
    queue_block: BaseQueueBlock = None

    network_id: int = 0
    min_time_between_blocks: int = 0


    @abstractmethod
    def __init__(self, header, chaindb):
        pass

    @classmethod
    @abstractmethod
    def with_zero_min_time_between_blocks(cls) -> Type['BaseVM']:
        raise NotImplementedError("VM classes must implement this method")

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
                            this_chain_address: Address,
                            validate: bool = True) -> Tuple[BlockHeader, Receipt, BaseComputation]:
        raise NotImplementedError("VM classes must implement this method")

    @abstractmethod
    def apply_receive_transaction(self,
                               header: BlockHeader,
                               receive_transaction: BaseReceiveTransaction,
                               this_chain_address: Address,
                               validate: bool = True) -> Tuple[Optional[BlockHeader],
                                                               Optional[Receipt],
                                                               BaseComputation]:
        raise NotImplementedError("VM classes must implement this method")

    @abstractmethod
    def generate_transaction_for_single_computation(self,
                                                    tx_data: bytes,
                                                    from_address: Address,
                                                    to_address: Address
                                                    ) -> SpoofTransaction:
        raise NotImplementedError("VM classes must implement this method")

    @abstractmethod
    def compute_single_transaction(self, transaction: Union[BaseTransaction, SpoofTransaction]) -> BaseComputation:
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
                         code_address=None) -> BaseComputation:
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
    
    

    @abstractmethod
    def reverse_pending_transactions(self, block_header: BaseBlockHeader) -> None:
        raise NotImplementedError("VM classes must implement this method")

    #
    # Mining
    #
    @abstractmethod
    def import_block(self, block: Union[BaseBlock, BaseQueueBlock], validate: bool = True, private_key: PrivateKey = None) -> BaseBlock:
        raise NotImplementedError("VM classes must implement this method")


    # @abstractmethod
    # def set_block_transactions(self, base_block, new_header, transactions, receipts):
    #     raise NotImplementedError("VM classes must implement this method")

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


    # @classmethod
    # @abstractmethod
    # def get_prev_hashes(cls, last_block_hash, chaindb):
    #     raise NotImplementedError("VM classes must implement this method")

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
    def save_recievable_transactions(self,
                                     block_header_hash: Hash32,
                                     send_computations: List[BaseComputation],
                                     receive_computations: List[BaseComputation]) -> None:
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

    def __init__(self, header: BlockHeader, chaindb: BaseChainDB, network_id: int):
        self.chaindb = chaindb
        self.consensus_db = self.consensus_db_class(chaindb)
        self.network_id = network_id
        self.header = header

    def __repr__(self) -> str:
        return '<{class_name}>'.format(
            class_name=self.__class__.__name__
        )

    @classmethod
    def with_zero_min_time_between_blocks(cls) -> Type[BaseVM]:
        new_class = cls
        new_class.min_time_between_blocks = 0
        return new_class


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
            self._state = self.get_state_class()(db=self.chaindb.db, execution_context=self.header.create_execution_context(self.network_id))
        return self._state

    @state.setter
    def state(self, val):
        self._state = val

    def refresh_state(self) -> None:
        self.state = self.get_state_class()(
            db=self.chaindb.db,
            execution_context=self.header.create_execution_context(self.network_id)
        )

    #
    # Execution
    #
    def apply_all_transactions(self, block: BaseBlock, private_key: PrivateKey = None, is_queue_block = False) -> Tuple[BaseBlockHeader,
                                                                                                                  List[Receipt],
                                                                                                                  List[BaseComputation],
                                                                                                                  List[BaseComputation],
                                                                                                                  List[BaseTransaction],
                                                                                                                  List[BaseReceiveTransaction]]:

        #run all of the transactions.
        last_header, receipts, send_computations = self._apply_all_send_transactions(block.transactions, block.header)


        #then run all receive transactions
        last_header, receive_receipts, receive_computations, processed_receive_transactions = self._apply_all_receive_transactions(block.receive_transactions, last_header, is_queue_block=is_queue_block)

        # then combine
        receipts.extend(receive_receipts)

        return last_header, receipts, receive_computations, send_computations, [], processed_receive_transactions

    def apply_send_transaction(self,
                               header: BlockHeader,
                               transaction: BaseTransaction,
                               this_chain_address: Address,
                               validate: bool = True) -> Tuple[BlockHeader, Receipt, BaseComputation]:
        """
        Apply the transaction to the current block. This is a wrapper around
        :func:`~hvm.vm.state.State.apply_transaction` with some extra orchestration logic.

        :param header: header of the block before application
        :param transaction: to apply
        """
        #this_chain_address = header.sender
        #this is a send transaction
        send_transaction = transaction
        receive_transaction = None
        if validate:
            self.validate_transaction_against_header(header, send_transaction=send_transaction)


        computation = self.state.apply_transaction(send_transaction = send_transaction,
                                                   this_chain_address = this_chain_address,
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
                               this_chain_address: Address,
                               validate: bool = True) -> Tuple[Optional[BlockHeader],
                                                               Optional[Receipt],
                                                               BaseComputation]:
        """
        Apply the transaction to the current block. This is a wrapper around
        :func:`~hvm.vm.state.State.apply_transaction` with some extra orchestration logic.

        :param header: header of the block before application
        :param transaction: to apply
        """
        # Lets make sure we have this receivable transaction in the account
        receivable_tx_key = self.state.account_db.get_receivable_transaction(this_chain_address, receive_transaction.send_transaction_hash)

        # Very first thing, check to see if this transaction has been received before:
        try:
            block_hash, index, is_receive = self.chaindb.get_transaction_index(receive_transaction.hash)
            if self.chaindb.is_in_canonical_chain(block_hash):
                raise ValidationError(
                    'Tried to import a receive transaction that has already been received in the canonical chain')
        except TransactionNotFound:
            pass

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

            raise ReceivableTransactionNotFound("this_chain_address = {}, send_transaction_hash = {}, sender_block_hash = {}".format(
                encode_hex(this_chain_address),
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

                    if refund_transaction.referenced_send_transaction is None:
                        raise ValidationError("This refund transaction does not have a populated reference transaction. "
                                              "The chain should have populated this. "
                                              "Make sure the transaction wasn't copied somewhere without copying the reference transaction.")

                    receive_transaction = refund_transaction.referenced_send_transaction
                    
                    # Make sure the refund amount is the same as we computed
                    local_refund_amount = self.state.account_db.get_refund_amount_for_transaction(receive_transaction.hash)
                    if refund_transaction.refund_amount != local_refund_amount:
                        raise ValidationError("The refund transaction refund_amount does not match the refund amount that we calculated locally. "
                                              "Refund amount given: {} | refund amount calculated locally: {} | receive transaction hash: {}".format(
                            refund_transaction.refund_amount,
                            local_refund_amount,
                            encode_hex(receive_transaction.hash)
                        ))
                else:
                    refund_transaction = None



                block_hash, index, is_receive = self.chaindb.get_transaction_index(receive_transaction.send_transaction_hash)

                if block_hash != receive_transaction.sender_block_hash:
                    raise ValidationError(
                        "The sender_block_hash of this receive transaction doesn't match the block of the send transaction")

                if is_receive:
                    raise ValidationError(
                        "This receive transaction references another receive transaction. This is not allowed.")

                if receive_transaction.referenced_send_transaction is None:
                    raise ValidationError("This receive transaction does not have a populated reference transaction. "
                                          "The chain should have populated this. "
                                          "Make sure the transaction wasn't copied somewhere without copying the reference transaction.")

                send_transaction = receive_transaction.referenced_send_transaction

            except TransactionNotFound:
                raise ReceivableTransactionNotFound()


            # we assume past this point that, if it is a receive transaction, the send transaction exists in account
            computation = self.state.apply_transaction(send_transaction=send_transaction,
                                                       this_chain_address=this_chain_address,
                                                       receive_transaction=receive_transaction,
                                                       refund_transaction=refund_transaction,
                                                       validate=validate)

            if validate:
                receipt = self.make_receipt(header, computation, send_transaction, receive_transaction, refund_transaction)
                new_header = self.apply_receipt_to_header(header, receipt)
                return new_header, receipt, computation
            else:
                return None, None, computation

    def _apply_reward_bundle(self, reward_bundle: StakeRewardBundle, block_timestamp: Timestamp, wallet_address: Address, validate = True) -> None:

        if validate:
            self.consensus_db.validate_reward_bundle(reward_bundle, chain_address=wallet_address, block_timestamp = block_timestamp)

        self.state.apply_reward_bundle(reward_bundle, wallet_address)

    def generate_transaction_for_single_computation(self,
                                                   tx_data: bytes,
                                                   from_address: Address,
                                                   to_address: Address,
                                                   **kwargs,
                                                   ) -> SpoofTransaction:
        tx_nonce = self.state.account_db.get_nonce(from_address)

        transaction = self.create_transaction(
            gas_price=0x01,
            gas=BLOCK_GAS_LIMIT,
            to=to_address,
            value=0,
            nonce=tx_nonce,
            data=tx_data,
        )

        return SpoofTransaction(transaction, from_=from_address)


    def compute_single_transaction(self, transaction: Union[BaseTransaction, SpoofTransaction]) -> BaseComputation:
        '''
        Passthrough for state. Used only to get the computation result of a single transaction.
        :param transaction:
        :return:
        '''
        return self.state.compute_single_transaction(transaction, self.header.chain_address)


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
                         ) -> BaseComputation:
        """
        Execute raw bytecode in the context of the current state of
        the virtual machine.
        """
        if origin is None:
            origin = sender

        # message = Message(
        #     gas=message_gas,
        #     to=send_transaction.to,
        #     sender=send_transaction.sender,
        #     value=send_transaction.value,
        #     data=data,
        #     code=code,
        #     create_address=contract_address,
        #     refund_amount=refund_amount,
        # )

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

        # return self.vm_state.get_transaction_context_class()(
        #     origin=send_transaction.sender,
        #     gas_price=send_transaction.gas_price,
        #     send_tx_hash=send_transaction.hash,
        #     this_chain_address=this_chain_address,
        #     is_receive=is_receive,
        #     is_refund=is_refund,
        #     receive_tx_hash=receive_transaction_hash,
        # )

        # Construction a tx context
        transaction_context = self.state.get_transaction_context_class()(
            gas_price=gas_price,
            origin=origin,
            this_chain_address=origin,
            send_tx_hash=ZERO_HASH32
        )

        # Execute it in the VM
        return self.state.get_computation(message, transaction_context).apply_computation(
            self.state,
            message,
            transaction_context,
        )


    def _apply_all_send_transactions(self, transactions, base_header, validate = True) -> Tuple[BlockHeader, List[Receipt], List[BaseComputation]]:
        receipts = []
        previous_header = base_header
        result_header = base_header
        computations = []

        this_chain_address = base_header.chain_address

        if validate:
            for transaction in transactions:
                result_header, receipt, computation = self.apply_send_transaction(previous_header, transaction, this_chain_address, validate = validate)

                previous_header = result_header
                receipts.append(receipt)
                computations.append(computation)
    
            return result_header, receipts, computations
        else:
            for transaction in transactions:
                result_header, receipt, computation = self.apply_send_transaction(previous_header, transaction, validate = validate)
                computations.append(computation)
            return result_header, [], computations

    def _apply_all_receive_transactions(self, transactions, base_header, validate=True, is_queue_block = False) -> Tuple[BlockHeader, List[Receipt], List[BaseComputation], List[BaseReceiveTransaction]]:
        receipts = []
        previous_header = base_header
        result_header = base_header
        computations = []
        processed_transactions = []

        this_chain_address = base_header.chain_address
        if validate:
            for transaction in transactions:
                try:
                    result_header, receipt, computation = self.apply_receive_transaction(previous_header, transaction,
                                                                                      this_chain_address,
                                                                                      validate=validate)

                except RequiresCodeFromMissingChain as e:
                    # If it is a queueblock, delete the receivable and import block without it
                    if is_queue_block:
                        # Discard all changes to the state by getting a new state, then delete the receivable transaction, and persist.
                        self.state.account_db.save_receivable_transaction_as_not_imported(this_chain_address, transaction.send_transaction_hash)
                        continue
                    else:
                        raise e
                except RequiresCodeFromChainInFuture as e:
                    # If it is a queueblock, delete the receivable and import block without it
                    if is_queue_block:
                        self.state.account_db.save_receivable_transaction_as_not_imported(this_chain_address, transaction.send_transaction_hash)
                        continue
                    else:
                        raise e

                previous_header = result_header
                receipts.append(receipt)
                computations.append(computation)
                processed_transactions.append(transaction)


            return result_header, receipts, computations, processed_transactions
        else:
            for transaction in transactions:
                result_header, receipt, computation = self.apply_receive_transaction(previous_header, transaction,
                                                                                  validate=validate)
                computations.append(computation)
            return result_header, [], computations



    def reverse_pending_transactions(self, block_header: BaseBlockHeader) -> None:
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
                
    def apply_receipt_to_header(self, base_header: BlockHeader, receipt: Receipt) -> BlockHeader:
        new_header = base_header.copy(
            bloom=int(BloomFilter(base_header.bloom) | receipt.bloom),
            gas_used=receipt.gas_used,
        )
        return new_header


    #
    # Mining
    #

    def add_computation_call_nonce_to_execution_context(self, block):
        if len(block.transactions) == 0:
            nonce = self.state.account_db.get_nonce(block.header.chain_address)
        else:
            nonce = block.transactions[-1].nonce + 1

        self.state.execution_context.computation_call_nonce = nonce

    def copy_referenced_transactions(self, receive_transactions_from: List[BaseReceiveTransaction], receive_transactions_to: List[BaseReceiveTransaction]):
        # This assumes the two lists are in order.
        if len(receive_transactions_from) != len(receive_transactions_to):
            raise ValidationError("The number of receive transactions has changed while importing the block. This shouldn't happen.")
        for i in range(len(receive_transactions_from)):
            current_transaction_from = receive_transactions_from[i]
            current_transaction_to = receive_transactions_to[i]
            current_transaction_to.referenced_send_transaction = current_transaction_from.referenced_send_transaction

            if current_transaction_to.is_refund:
                current_transaction_from = current_transaction_from.referenced_send_transaction
                current_transaction_to = current_transaction_to.referenced_send_transaction
                current_transaction_to.referenced_send_transaction = current_transaction_from.referenced_send_transaction

    def import_block(self, block: Union[BaseBlock, BaseQueueBlock], validate: bool = True, private_key: PrivateKey = None, **kwargs) -> BaseBlock:
        """
        Import the given block to the chain.
        """
        self.add_computation_call_nonce_to_execution_context(block)

        # Ensure that this is the correct VM for the block being imported. The timestamp must match that
        # of the header in this VM.
        if block.header.timestamp != self.header.timestamp:
            raise ValidationError("This VM is valid for a timestamp that differs from the timestamp of the block being imported."
                                  "The timestamp of this VM is {}, and the timestamp of the block being imported is {}".format(self.header.timestamp, block.header.timestamp))


        if isinstance(block, self.get_queue_block_class()):
            is_queue_block = True
            head_block = self.queue_block
            if private_key is None:
                raise ValueError("Cannot import queueblock because no private key given for signing.")

        else:
            is_queue_block = False
            head_block = self.block
            if (block.sender != block.header.chain_address and not self.state.account_db.is_smart_contract(block.header.chain_address)):
                raise BlockOnWrongChain("Tried to import a block that doesnt belong on this chain.")

        # Base the block off of the existing head block so that parameters are correct. Then after importing we will
        # check to make sure the block is unchanged to catch any invalid parameters of the original block.
        block = head_block.copy(
            header=self.configure_header(
                gas_limit=block.header.gas_limit,
                gas_used=0,
                extra_data=block.header.extra_data,
                v=block.header.v,
                r=block.header.r,
                s=block.header.s,
            ),
            transactions = block.transactions,
            receive_transactions = block.receive_transactions,
            reward_bundle = block.reward_bundle
        )

        # We need to re-initialize the `state` to update the execution context.
        # We don't need to refresh the state because it should have just been created for this block.
        # self.refresh_state()

        last_header, receipts, receive_computations, send_computations, computation_call_send_transactions, processed_receive_transactions = self.apply_all_transactions(block, private_key = private_key, is_queue_block = is_queue_block)

        if is_queue_block:
            # need to add any new computation call send transactions to the list of send transactions
            if len(computation_call_send_transactions) > 0:
                self.logger.debug("Adding computation call send transactions to block send transactions for queue block")
                existing_transactions = list(block.transactions)
                existing_transactions.extend(computation_call_send_transactions)
                block = block.copy(transactions = existing_transactions, receive_transactions = processed_receive_transactions)
            else:
                if len(block.receive_transactions) != len(processed_receive_transactions):
                    block = block.copy(receive_transactions=processed_receive_transactions)

            try:
                # Make sure we haven't removed all of the transactions because they were invalid.
                block.validate_has_content()
            except RewardAmountRoundsToZero:
                raise RewardAmountRoundsToZero("All receive transactions for this block were invalid. Import aborted.")

        # new transaction count limit - check after adding computation call transactions:
        transaction_count = len(block.transactions) + len(block.receive_transactions)
        if transaction_count > BLOCK_TRANSACTION_LIMIT:
            raise ValidationError("The block has to many transactions (including transactions generated by computations). "
                                  "It has {} transactions, but is only allowed a max of {}".format(transaction_count, BLOCK_TRANSACTION_LIMIT))

        if not (block.reward_bundle.reward_type_1.amount == 0 and block.reward_bundle.reward_type_2.amount == 0):
            self._apply_reward_bundle(block.reward_bundle, block.header.timestamp, block.header.chain_address, validate=validate)


        #
        # Setting block parameters, and saving transaction and receipt tries
        #

        # Send tx
        sent_tx_root_hash, _ = self.save_items_to_db_as_trie(block.transactions)
        receipt_root_hash, _ = self.save_items_to_db_as_trie(receipts)

        # Receive tx
        receive_tx_root_hash, _ = self.save_items_to_db_as_trie(block.receive_transactions)

        # Reward bundle
        if block.reward_bundle is None:
            reward_hash = BLANK_REWARD_HASH
        else:
            reward_hash = block.reward_bundle.hash

        # Account hash
        account_hash = self.state.account_db.get_account_hash(block.header.chain_address)

        # Account balance
        account_balance = self.state.account_db.get_balance(block.header.chain_address)

        block = block.copy(
            header=last_header.copy(
                transaction_root=sent_tx_root_hash,
                receipt_root=receipt_root_hash,
                receive_transaction_root=receive_tx_root_hash,
                reward_hash=reward_hash,
                account_hash=account_hash,
                account_balance=account_balance,
            ),
        )
        
        if is_queue_block:
            """
            If it is a queueblock, then it must be signed now.
            It cannot be signed earlier because the header fields were changing
            """

            # change any final header parameters before signing
            block = self.pack_block(block, **kwargs)
            self.logger.debug("signing block")
            block = block.as_complete_block(private_key, self.network_id)
            
        # Delete all receivable transactions that have been received in this block
        # Moved this from within the computation executor because it can revert memory on error, which will put the transactions back even though they were received already.

        for tx in block.receive_transactions:
            self.state.account_db.delete_receivable_transaction(block.header.chain_address, tx.send_transaction_hash)

        
        #save all send transactions in the state as receivable
        #we have to do this at the end here because the block hash is still changing when transactions are being processed.

        self.save_recievable_transactions(block.header.hash, send_computations, receive_computations)

        if validate:
            # Perform validation
            self.validate_block(block)
            self.validate_computation_call_send_transactions_against_block(block, computation_call_send_transactions)
        
        #state is persisted from chain after ensuring block unchanged

        return block



        

    def save_recievable_transactions(self,
                                     block_header_hash: Hash32,
                                     send_computations: List[BaseComputation],
                                     receive_computations: List[BaseComputation]) -> None:
        '''
        Saves send transactions as receivable. This requires the computations to cover transactions that deploy a contract to a new storage address.
        In that case, we need the computation to know what the storage address is.
        This also saves any receive transactions containing a refund as receivable.
        :param block_header_hash:
        :param computations:
        :param receive_transactions:
        :return:
        '''
        for computation in send_computations:
            msg = computation.msg
            transaction_context = computation.transaction_context
            if not computation.is_error:
                self.state.account_db.add_receivable_transaction(msg.resolved_to,
                                                                 transaction_context.send_tx_hash,
                                                                 block_header_hash,
                                                                 msg.is_create)

        # Refunds skipped here because there are none for the standard fork. This function is overwritten in photon


            
    def delete_transaction_as_receivable(self, wallet_address, transaction_hash):
        try:
            self.state.account_db.delete_receivable_transaction(wallet_address, transaction_hash)
        except ReceivableTransactionNotFound:
            pass
        
    def delete_transactions_as_receivable(self,transactions, receive_transactions):
        for transaction in transactions:
            self.delete_transaction_as_receivable(transaction.to, transaction.hash)

        for receive_transaction in receive_transactions:
            if not receive_transaction.is_refund:
                if self.state.account_db.get_refund_amount_for_transaction(receive_transaction.hash) > 0:
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



#     def set_block_reward_hash(self, block: BaseBlock, header:BlockHeader, reward_bundle: StakeRewardBundle) -> BaseBlock:
#         if reward_bundle is None:
#             reward_hash = BLANK_REWARD_HASH
#         else:
#             reward_hash = reward_bundle.hash
#
#         return block.copy(
#             reward_bundle=reward_bundle,
#             header=header.copy(
#                 reward_hash=reward_hash
#             ),
#         )
#
#
#     def set_block_transactions(self, base_block, new_header, transactions, receipts):
#         tx_root_hash, tx_kv_nodes = self.save_items_to_db_as_trie(transactions)
#         receipt_root_hash, receipt_kv_nodes = self.save_items_to_db_as_trie(receipts)
#
#
#         return base_block.copy(
#             transactions=transactions,
#             header=new_header.copy(
#                 transaction_root=tx_root_hash,
#                 receipt_root=receipt_root_hash,
#             ),
#         )
#
#
#
#     def set_block_receive_transactions(self, base_block, new_header, transactions):
#         tx_root_hash, tx_kv_nodes = self.save_items_to_db_as_trie(transactions)
# #        tx_root_hash, tx_kv_nodes = make_trie_root_and_nodes(transactions)
# #        self.chaindb.persist_trie_data_dict(tx_kv_nodes)
#
#         return base_block.copy(
#             receive_transactions=transactions,
#             header=new_header.copy(
#                 receive_transaction_root=tx_root_hash
#             ),
#         )
#
#     def set_account_hash(self, block: BaseBlock):
#         account_hash = self.state.account_db.get_account_hash(self.wallet_address)
#         return block.copy(
#             header=block.header.copy(
#                 account_hash = account_hash
#             ),
#         )

    #
    # Finalization
    #
    # def save_closing_balance(self, block):
    #     closing_balance = self.state.account_db.get_balance(self.wallet_address)
    #
    #     return block.copy(
    #         header=block.header.copy(
    #             closing_balance = closing_balance
    #         ),
    #     )
            

        
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

        
    #
    # Transactions
    #
    def create_transaction(self, *args, **kwargs) -> BaseTransaction:
        """
        Proxy for instantiating a signed transaction for this VM.
        """
        return self.get_transaction_class()(*args, **kwargs)
    
    def create_receive_transaction(self, *args, **kwargs) -> BaseReceiveTransaction:
        """
        Proxy for instantiating a signed transaction for this VM.
        """
        return self.get_receive_transaction_class()(*args, **kwargs)
            
        
        
    @classmethod
    def get_transaction_class(cls) -> Type[BaseTransaction]:
        """
        Return the class that this VM uses for transactions.
        """
        return cls.get_block_class().get_transaction_class()
    
    @classmethod
    def get_receive_transaction_class(cls) -> Type[BaseReceiveTransaction]:
        """
        Return the class that this VM uses for transactions.
        """
        return cls.get_block_class().get_receive_transaction_class()

    #
    # Validate
    #
        
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
            if (block.header.timestamp - parent_header.timestamp) < self.min_time_between_blocks:
                raise ValidationError(
                    "The block has less than the minimum time between blocks\n"
                    "- block : {}\n"
                    "- block : {}\n"
                    "- parent: {}\n"
                    "- current timestamp : {}".format(
                        block,
                        block.header.timestamp,
                        parent_header.timestamp,
                        int(time.time())
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
    
    def validate_computation_call_send_transactions_against_block(self, block: BaseBlock, computation_call_send_transactions: List[BaseTransaction]) -> None:
        pass

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
    
        
