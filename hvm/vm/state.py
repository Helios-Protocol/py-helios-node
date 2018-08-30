from abc import (
    ABCMeta,
    abstractmethod
)
import logging
from typing import (  # noqa: F401
    Type,
    TYPE_CHECKING
)

from hvm.constants import (
    BLANK_ROOT_HASH,
    MAX_PREV_HEADER_DEPTH,
)
from hvm.exceptions import StateRootNotFound
from hvm.db.account import (  # noqa: F401
    BaseAccountDB,
    AccountDB,
)
from hvm.utils.datatypes import (
    Configurable,
)
from hvm.constants import (
    BLANK_ROOT_HASH,
)


if TYPE_CHECKING:
    from hvm.computation import (  # noqa: F401
        BaseComputation,
    )
    from hvm.vm.transaction_context import (  # noqa: F401
        BaseTransactionContext,
    )


class BaseState(Configurable, metaclass=ABCMeta):
    """
    The base class that encapsulates all of the various moving parts related to
    the state of the VM during execution.
    Each :class:`~hvm.vm.base.BaseVM` must be configured with a subclass of the
    :class:`~hvm.vm.state.BaseState`.

      .. note::

        Each :class:`~hvm.vm.state.BaseState` class must be configured with:

        - ``computation_class``: The :class:`~hvm.vm.computation.BaseComputation` class for
          vm execution.
        - ``transaction_context_class``: The :class:`~hvm.vm.transaction_context.TransactionContext`
          class for vm execution.
    """
    #
    # Set from __init__
    #
    __slots__ = ['_db', 'execution_context', 'account_db']

    computation_class = None  # type: Type[BaseComputation]
    transaction_context_class = None  # type: Type[BaseTransactionContext]
    account_db_class = None  # type: Type[BaseAccountDB]
    transaction_executor = None  # type: Type[BaseTransactionExecutor]

    def __init__(self, db, execution_context):
        self._db = db
        self.execution_context = execution_context
        self.account_db = self.get_account_db_class()(self._db)

    #
    # Logging
    #
    @property
    def logger(self):
        return logging.getLogger('hvm.vm.state.{0}'.format(self.__class__.__name__))

    #
    # Block Object Properties (in opcodes)
    #


    @property
    def timestamp(self):
        """
        Return the current ``timestamp`` from the current :attr:`~execution_context`
        """
        return self.execution_context.timestamp

    @property
    def block_number(self):
        """
        Return the current ``block_number`` from the current :attr:`~execution_context`
        """
        return self.execution_context.block_number


    @property
    def gas_limit(self):
        """
        Return the current ``gas_limit`` from the current :attr:`~transaction_context`
        """
        return self.execution_context.gas_limit

    #
    # Access to account db
    #
    @classmethod
    def get_account_db_class(cls):
        """
        Return the :class:`~hvm.db.account.BaseAccountDB` class that the
        state class uses.
        """
        if cls.account_db_class is None:
            raise AttributeError("No account_db_class set for {0}".format(cls.__name__))
        return cls.account_db_class
       
    def load_account_from_hash(self, account_hash, wallet_address):
        self.account_db.revert_to_account_from_hash(account_hash, wallet_address)
    
    def revert_account_to_hash_and_persist(self, account_hash, wallet_address):
        self.account_db.revert_to_account_from_hash(account_hash, wallet_address)
        self.account_db.persist()
        
    def revert_account_to_hash_keep_receivable_transactions_and_persist(self, account_hash, wallet_address):
        receivable_transactions = self.account_db.get_receivable_transactions(wallet_address)
        self.account_db.revert_to_account_from_hash(account_hash, wallet_address)
        self.account_db.add_receivable_transactions(wallet_address, receivable_transactions)
        self.account_db.persist()
        
    def clear_account_keep_receivable_transactions_and_persist(self, wallet_address):
        receivable_transactions = self.account_db.get_receivable_transactions(wallet_address)
        self.account_db.delete_account(wallet_address)
        self.account_db.add_receivable_transactions(wallet_address, receivable_transactions)
        self.account_db.persist()
        
        
    #   
    # Access self._chaindb
    #
    def snapshot(self):
        """
        Perform a full snapshot of the current state.

        Snapshots are a combination of the :attr:`~state_root` at the time of the
        snapshot and the id of the changeset from the journaled DB.
        """
        return self.account_db.record()

    def revert(self, snapshot):
        """
        Revert the VM to the state at the snapshot
        """
        changeset_id = snapshot

        # now roll the underlying database back
        self.account_db.discard(changeset_id)

    def commit(self, snapshot):
        """
        Commit the journal to the point where the snapshot was taken.  This
        will merge in any changesets that were recorded *after* the snapshot changeset.
        """
        checkpoint_id = snapshot
        self.account_db.commit(checkpoint_id)

    #
    # Access self.prev_hashes (Read-only)
    #
    def get_ancestor_hash(self, block_number):
        """
        Return the hash for the ancestor block with number ``block_number``.
        Return the empty bytestring ``b''`` if the block number is outside of the
        range of available block numbers (typically the last 255 blocks).
        """
        ancestor_depth = self.block_number - block_number - 1
        is_ancestor_depth_out_of_range = (
            ancestor_depth >= MAX_PREV_HEADER_DEPTH or
            ancestor_depth < 0 or
            ancestor_depth >= len(self.execution_context.prev_hashes)
        )
        if is_ancestor_depth_out_of_range:
            return b''
        ancestor_hash = self.execution_context.prev_hashes[ancestor_depth]
        return ancestor_hash

    #
    # Computation
    #
    def get_computation(self, message, transaction_context):
        """
        Return a computation instance for the given `message` and `transaction_context`
        """
        if self.computation_class is None:
            raise AttributeError("No `computation_class` has been set for this State")
        else:
            computation = self.computation_class(self, message, transaction_context)
        return computation

    #
    # Transaction context
    #
    @classmethod
    def get_transaction_context_class(cls):
        """
        Return the :class:`~hvm.vm.transaction_context.BaseTransactionContext` class that the
        state class uses.
        """
        if cls.transaction_context_class is None:
            raise AttributeError("No `transaction_context_class` has been set for this State")
        return cls.transaction_context_class

    #
    # Execution
    #
    def apply_transaction(self, transaction, validate = True):
        """
        Apply transaction to the vm state

        :param transaction: the transaction to apply
        :return: the new state root, and the computation
        """
        computation = self.execute_transaction(transaction, validate = validate)
        
        return computation

    def get_transaction_executor(self):
        return self.transaction_executor(self)

#    @abstractmethod
#    def execute_transaction(self):
#        raise NotImplementedError()
        
    def execute_transaction(self, transaction, validate = True):
        executor = self.get_transaction_executor()
        if executor == None:
            raise ValueError("No transaction executor given")
        return executor(transaction, validate = validate)


class BaseTransactionExecutor(metaclass=ABCMeta):
    def __init__(self, vm_state):
        self.vm_state = vm_state

    @abstractmethod
    def get_transaction_context(self, transaction):
        raise NotImplementedError()

    def __call__(self, transaction, validate = True):
        if validate:
            valid_transaction = self.validate_transaction(transaction)
        else:
            valid_transaction = transaction
        message = self.build_evm_message(valid_transaction)
        computation = self.build_computation(message, valid_transaction, validate)
        finalized_computation = self.finalize_computation(valid_transaction, computation)
        
        return finalized_computation

    @abstractmethod
    def validate_transaction(self):
        raise NotImplementedError()

    @abstractmethod
    def build_evm_message(self):
        raise NotImplementedError()

    @abstractmethod
    def build_computation(self):
        raise NotImplementedError()

    @abstractmethod
    def finalize_computation(self):
        raise NotImplementedError()
