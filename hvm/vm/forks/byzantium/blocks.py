from rlp_cython.sedes import (
    CountableList,
)
from hvm.rlp.headers import (
    BlockHeader,
)
from hvm.vm.forks.spurious_dragon.blocks import (
    SpuriousDragonBlock,
)

from .transactions import (
    ByzantiumTransaction,
)


class ByzantiumBlock(SpuriousDragonBlock):
    transaction_class = ByzantiumTransaction
    fields = [
        ('header', BlockHeader),
        ('transactions', CountableList(transaction_class)),
        ('uncles', CountableList(BlockHeader))
    ]
