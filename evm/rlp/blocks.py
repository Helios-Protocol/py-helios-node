from abc import (
    ABCMeta,
    abstractmethod
)
from typing import (  # noqa: F401
    Type
)

import rlp

from eth_typing import (
    Hash32
)

from evm.utils.datatypes import (
    Configurable,
)



class BaseBlock(rlp.Serializable, Configurable, metaclass=ABCMeta):
    transaction_class = None  # type: Type[BaseTransaction]

    @classmethod
    def get_transaction_class(cls) -> Type['BaseTransaction']:
        if cls.transaction_class is None:
            raise AttributeError("Block subclasses must declare a transaction_class")
        return cls.transaction_class
    
    @classmethod
    def get_receive_transaction_class(cls) -> Type['BaseTransaction']:
        if cls.receive_transaction_class is None:
            raise AttributeError("Block subclasses must declare a receive_transaction_class")
        return cls.receive_transaction_class

    @classmethod
    @abstractmethod
    def from_header(cls, header: 'BlockHeader', chaindb: 'BaseChainDB') -> 'BaseBlock':
        """
        Returns the block denoted by the given block header.
        """
        raise NotImplementedError("Must be implemented by subclasses")

    @property
    def sender(self):
        return self.header.sender
    
    @property
    @abstractmethod
    def hash(self) -> Hash32:
        raise NotImplementedError("Must be implemented by subclasses")

    @property
    @abstractmethod
    def number(self) -> int:
        raise NotImplementedError("Must be implemented by subclasses")

    @property
    def is_genesis(self) -> bool:
        return self.number == 0

    def __repr__(self) -> str:
        return '<{class_name}(#{b})>'.format(
            class_name=self.__class__.__name__,
            b=str(self),
        )

    def __str__(self) -> str:
        return "Block #{b.number}".format(b=self)


class BaseQueueBlock(BaseBlock):
    #variables to avoid python loops
    current_tx_nonce = None
    
    @abstractmethod
    def as_complete_block(self):
        raise NotImplementedError("Must be implemented by subclasses")
    
    @classmethod
    @abstractmethod
    def from_header(cls, header):
        raise NotImplementedError("Must be implemented by subclasses")
    
    @classmethod
    @abstractmethod
    def make_genesis_block(cls):
        raise NotImplementedError("Must be implemented by subclasses")
        
    def add_transaction(self, transaction):
        transactions = self.transactions + (transaction, )
        new_block = self.copy(
            transactions=transactions,
        )
        new_block.current_tx_nonce = transaction.nonce + 1
        return new_block
    
    def add_transactions(self, transactions):
        for tx in transactions:
            self.add_transaction(tx)
            
    def add_receive_transaction(self, receive_transaction):
        receive_transactions = self.receive_transactions + (receive_transaction, )
        
        return self.copy(
            receive_transactions=receive_transactions,
        )
    
    def add_receive_transactions(self, transactions):
        for tx in transactions:
            self.add_receive_transaction(tx)
    
    def contains_transaction(self, transaction):
        return transaction in self.transactions
    
    def contains_receive_transaction(self, transaction):
        return transaction in self.receive_transactions