from rlp_cython.sedes import (
    CountableList,
)
from hvm.rlp.headers import (
    BlockHeader,
)
from hvm.vm.forks.homestead.blocks import (
    HomesteadBlock,
)
from .transactions import (
    SpuriousDragonTransaction,
)


class SpuriousDragonBlock(HomesteadBlock):
    transaction_class = SpuriousDragonTransaction
    fields = [
        ('header', BlockHeader),
        ('transactions', CountableList(transaction_class)),
        ('uncles', CountableList(BlockHeader))
    ]
