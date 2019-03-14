from rlp_cython.sedes import (
    CountableList,
)
from hvm.rlp.headers import (
    BlockHeader,
    MicroBlockHeader)

from eth_bloom import (
    BloomFilter,
)
from .transactions import (
    HeliosTestnetTransaction,
    HeliosTestnetReceiveTransaction,
)
from hvm.rlp.blocks import (
    BaseBlock,
    BaseQueueBlock,
    BaseMicroBlock)
from hvm.rlp.receipts import (
    Receipt,
)
from hvm import constants
import time

from eth_typing import Address

from hvm.rlp.consensus import StakeRewardBundle

#this one is just used to decode blocks that come in through RPC
class MicroBlock(BaseMicroBlock):

    fields = [
        ('header', MicroBlockHeader),
        ('transactions', CountableList(HeliosTestnetTransaction)),
        ('receive_transactions', CountableList(HeliosTestnetReceiveTransaction)),
        ('reward_bundle', StakeRewardBundle),
    ]

class HeliosTestnetBlock(BaseBlock):
    transaction_class = HeliosTestnetTransaction
    receive_transaction_class = HeliosTestnetReceiveTransaction
    header_class = BlockHeader
    reward_bundle_class = StakeRewardBundle
    receipt_class = Receipt

    fields = [
        ('header', header_class),
        ('transactions', CountableList(transaction_class)),
        ('receive_transactions', CountableList(receive_transaction_class)),
        ('reward_bundle', reward_bundle_class),
    ]

    bloom_filter = None

    def __init__(self, header, transactions=None, receive_transactions=None, reward_bundle = None):
        if transactions is None:
            transactions = []
            
        if receive_transactions is None:
            receive_transactions = []

        if reward_bundle is None:
            reward_bundle = StakeRewardBundle()


        self.bloom_filter = BloomFilter(header.bloom)

        super(HeliosTestnetBlock, self).__init__(
            header=header,
            transactions=transactions,
            receive_transactions=receive_transactions,
            reward_bundle = reward_bundle,
        )

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
        # TODO:Remove
        return cls.transaction_class
    
    #
    # Receive transaction class for this block class
    #
    @classmethod
    def get_receive_transaction_class(cls):
        #TODO:Remove
        return cls.receive_transaction_class

    #
    # Reward bundle class for this block class
    #
    @classmethod
    def get_reward_bundle_class(cls):
        # TODO:Remove
        return cls.reward_bundle_class


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
        #TODO:Remove. It is dirty to have to pass the chaindb into here.
        transactions = chaindb.get_block_transactions(header, cls.transaction_class)
        receive_transactions = chaindb.get_block_receive_transactions(header, cls.receive_transaction_class)
        reward_bundle = chaindb.get_reward_bundle(header.reward_hash, cls.reward_bundle_class)

        return cls(
            header=header,
            transactions=transactions,
            receive_transactions=receive_transactions,
            reward_bundle = reward_bundle
        )

    #
    # Microblock API
    #
    @classmethod
    def from_micro_block(cls, micro_block: MicroBlock):
        header = cls.header_class.from_micro_header(micro_block.header)
        return cls(
            header=header,
            transactions=micro_block.transactions,
            receive_transactions=micro_block.receive_transactions,
            reward_bundle=micro_block.reward_bundle,
        )

class HeliosTestnetQueueBlock(HeliosTestnetBlock,BaseQueueBlock):
    transaction_class = HeliosTestnetTransaction
    receive_transaction_class = HeliosTestnetReceiveTransaction
    reward_bundle_class = StakeRewardBundle
    receipt_class = Receipt

    fields = [
        ('header', BlockHeader),
        ('transactions', CountableList(transaction_class)),
        ('receive_transactions', CountableList(receive_transaction_class)),
        ('reward_bundle', StakeRewardBundle),
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
            header=header.copy(
                    gas_used = 0,
                    v = 0,
                    r = 0,
                    s = 0
                    ),
            transactions=transactions,
            receive_transactions=receive_transactions,
            reward_bundle=StakeRewardBundle(),
        )
    
    @classmethod
    def make_genesis_block(cls, chain_address: Address):
        genesis_header = BlockHeader(
            chain_address=chain_address,
            account_hash=constants.GENESIS_ACCOUNT_HASH,
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

        return HeliosTestnetBlock(signed_header, self.transactions, self.receive_transactions, self.reward_bundle)

            
           
            