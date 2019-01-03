from rlp_cython.sedes import (
    CountableList,
)
from hvm.rlp.headers import (
    BlockHeader,
)
from hvm.vm.forks.frontier.blocks import (
    FrontierBlock,
)
from .transactions import (
    HomesteadTransaction,
)


class HomesteadBlock(FrontierBlock):
    transaction_class = HomesteadTransaction
    fields = [
        ('header', BlockHeader),
        ('transactions', CountableList(transaction_class)),
        ('uncles', CountableList(BlockHeader))
    ]
