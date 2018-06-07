from rlp.sedes import (
    CountableList,
)
from evm.rlp.headers import (
    BlockHeader,
)

from eth_bloom import (
    BloomFilter,
)
from .transactions import (
    HeliosTestnetTransaction,
    HeliosTestnetReceiveTransaction,
)
from evm.rlp.blocks import (
    BaseBlock,
    BaseQueueBlock,
)
from evm.rlp.receipts import (
    Receipt,
)
from evm import constants
import time

class HeliosTestnetBlock(BaseBlock):
    transaction_class = HeliosTestnetTransaction
    receive_transaction_class = HeliosTestnetReceiveTransaction
    fields = [
        ('header', BlockHeader),
        ('transactions', CountableList(transaction_class)),
        ('receive_transactions', CountableList(receive_transaction_class))
    ]

    bloom_filter = None

    def __init__(self, header, transactions=None, receive_transactions=None):
        if transactions is None:
            transactions = []
            
        if receive_transactions is None:
            receive_transactions = []

        self.bloom_filter = BloomFilter(header.bloom)

        super(HeliosTestnetBlock, self).__init__(
            header=header,
            transactions=transactions,
            receive_transactions=receive_transactions,
        )
        # TODO: should perform block validation at this point?

    #
    # Helpers
    #
    @property
    def number(self):
        return self.header.block_number

    @property
    def hash(self):
        return self.header.hash

    #
    # Transaction class for this block class
    #
    @classmethod
    def get_transaction_class(cls):
        return cls.transaction_class
    
    #
    # Transaction class for this block class
    #
    @classmethod
    def get_receive_transaction_class(cls):
        return cls.receive_transaction_class

    #
    # Receipts API
    #
    def get_receipts(self, chaindb):
        return chaindb.get_receipts(self.header, Receipt)

    #
    # Header API
    #
    @classmethod
    def from_header(cls, header, chaindb):
        """
        Returns the block denoted by the given block header.
        """
        transactions = chaindb.get_block_transactions(header, cls.get_transaction_class())
        receive_transactions = chaindb.get_block_receive_transactions(header, cls.get_receive_transaction_class())

        return cls(
            header=header,
            transactions=transactions,
            receive_transactions=receive_transactions
        )


class HeliosTestnetQueueBlock(HeliosTestnetBlock,BaseQueueBlock):
    transaction_class = HeliosTestnetTransaction
    receive_transaction_class = HeliosTestnetReceiveTransaction
    fields = [
        ('header', BlockHeader),
        ('transactions', CountableList(transaction_class)),
        ('receive_transactions', CountableList(receive_transaction_class))
    ]
    #
    # Header API
    #
    @classmethod
    def from_header(cls, header):
        """
        Returns the block denoted by the given block header.
        """
#        if not isinstance(header, UnsignedBlockHeader):
#            header = header.create_unsigned_block_header_from_self()
#            
        #creating a new queueblock means it has no transactions yet
        transactions = [] 
        receive_transactions = []

        return cls(
            header=header,
            transactions=transactions,
            receive_transactions=receive_transactions,
        )
    
    @classmethod
    def make_genesis_block(cls):
        genesis_header = BlockHeader(
            closing_balance=0,
            extra_data=constants.GENESIS_EXTRA_DATA,
            gas_limit=constants.GENESIS_GAS_LIMIT,
            gas_used=0,
            bloom=0,
            block_number=0,
            parent_hash=constants.GENESIS_PARENT_HASH,
            receipt_root=constants.BLANK_ROOT_HASH,
            timestamp=int(time.time()),
            transaction_root=constants.BLANK_ROOT_HASH,
            receive_transaction_root=constants.BLANK_ROOT_HASH,
        )
        return cls.from_header(genesis_header)
        



    def as_complete_block(self, private_key, chain_id):
        #first lets sign the header
        """
        signs the header of the given block and changes it to a complete block
        doesnt validate the header before doing so
        """
        
        signed_header = self.header.get_signed(private_key, chain_id)

        return HeliosTestnetBlock(signed_header, self.transactions, self.receive_transactions)

            
           
            