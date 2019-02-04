from abc import (
    ABCMeta,
    abstractmethod
)
from typing import (  # noqa: F401
    Type
)

import rlp_cython as rlp

from eth_typing import (
    Hash32,
    Address
)
from hvm.rlp.receipts import Receipt

from hvm.utils.datatypes import (
    Configurable,
)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hvm.rlp.transactions import BaseTransaction, BaseReceiveTransaction
    from hvm.rlp.consensus import StakeRewardBundle

class BaseMicroBlock(rlp.Serializable, Configurable, metaclass=ABCMeta):
    pass


class BaseBlock(rlp.Serializable, Configurable, metaclass=ABCMeta):
    transaction_class: 'Type[BaseTransaction]' = None
    receive_transaction_class: 'Type[BaseReceiveTransaction]' = None
    reward_bundle_class: 'Type[StakeRewardBundle]' = None
    receipt_class: Type[Receipt] = None

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

    def to_dict(self):
        block = {}
        header = {}

        parameter_names = list(dict(self.header._meta.fields).keys())
        for parameter_name in parameter_names:
            header[parameter_name] = getattr(self.header, parameter_name)

        transactions = []
        for tx in self.transactions:
            transaction = {}
            parameter_names = list(dict(tx._meta.fields).keys())
            for parameter_name in parameter_names:
                transaction[parameter_name] = getattr(tx, parameter_name)
            transactions.append(transaction)

        receive_transactions = []
        for tx in self.receive_transactions:
            transaction = {}
            parameter_names = list(dict(tx._meta.fields).keys())
            for parameter_name in parameter_names:
                transaction[parameter_name] = getattr(tx, parameter_name)
            receive_transactions.append(transaction)


        reward_type_2_proof = []
        for proof in self.reward_bundle.reward_type_2.proof:
            reward_type_2_proof.append(proof.as_dict())


        block['header'] = header
        block['transactions'] = transactions
        block['receive_transactions'] = receive_transactions

        block['reward_bundle'] = {'reward_type_1': {'amount': self.reward_bundle.reward_type_1.amount},
                                  'reward_type_2': {'amount': self.reward_bundle.reward_type_1.amount,
                                                    'proof': reward_type_2_proof}}
        return block

    @classmethod
    def from_dict(cls, block_as_dict):


        transaction_class = cls.transaction_class
        receive_transaction_class = cls.receive_transaction_class
        reward_bundle_class = cls.reward_bundle_class
        header_class = cls.header_class
        #block_class = cls.__class__()

        header = header_class(**block_as_dict['header'])

        transactions = []
        for tx in block_as_dict['transactions']:
            transaction = transaction_class(**tx)
            transactions.append(transaction)

        receive_transactions = []
        for tx in block_as_dict['receive_transactions']:
            transaction = receive_transaction_class(**tx)
            receive_transactions.append(transaction)

        reward_type_2_proof = []
        for proof in block_as_dict['reward_bundle']['reward_type_2']['proof']:
            proof = reward_bundle_class.reward_type_2_class.proof_class(**proof)
            reward_type_2_proof.append(proof)

        reward_type_1 = reward_bundle_class.reward_type_1_class(block_as_dict['reward_bundle']['reward_type_1']['amount'])
        reward_type_2 = reward_bundle_class.reward_type_2_class(block_as_dict['reward_bundle']['reward_type_1']['amount'],
                                         reward_type_2_proof)
        reward_bundle = reward_bundle_class(reward_type_1, reward_type_2)
        new_block = cls(header = header,
                        transactions = transactions,
                        receive_transactions = receive_transactions,
                        reward_bundle = reward_bundle)

        return new_block

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
    def make_genesis_block(cls, chain_address: Address):
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