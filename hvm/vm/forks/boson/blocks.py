from hvm.vm.forks.helios_testnet.blocks import MicroBlock, HeliosTestnetBlock, HeliosTestnetQueueBlock
from rlp_cython.sedes import (
    CountableList,
)
from hvm.rlp.headers import (
    BlockHeader,
    MicroBlockHeader)

from .transactions import (
    HeliosTestnetTransaction,
    HeliosTestnetReceiveTransaction,
    BosonReceiveTransaction, BosonTransaction)

from hvm.rlp.receipts import (
    Receipt,
)
from hvm.rlp.consensus import StakeRewardBundle

class BosonMicroBlock(MicroBlock):

    fields = [
        ('header', MicroBlockHeader),
        ('transactions', CountableList(BosonTransaction)),
        ('receive_transactions', CountableList(BosonReceiveTransaction)),
        ('reward_bundle', StakeRewardBundle),
    ]

class BosonBlock(HeliosTestnetBlock):
    transaction_class = BosonTransaction
    receive_transaction_class = BosonReceiveTransaction
    header_class = BlockHeader
    reward_bundle_class = StakeRewardBundle
    receipt_class = Receipt

    fields = [
        ('header', header_class),
        ('transactions', CountableList(transaction_class)),
        ('receive_transactions', CountableList(receive_transaction_class)),
        ('reward_bundle', reward_bundle_class),
    ]



class BosonQueueBlock(BosonBlock,HeliosTestnetQueueBlock):
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
