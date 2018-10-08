from typing import (
    Tuple,
    Type,
    TYPE_CHECKING
)

from hvm.vm.base import BaseVM

from hp2p.peer import BasePeerContext

from helios.db.base import AsyncBaseDB
from helios.db.chain import AsyncChainDB
from helios.db.chain_head import AsyncChainHeadDB
from hvm.chains import AsyncChain

if TYPE_CHECKING:
    from helios.config import ChainConfig


class ChainContext(BasePeerContext):
    def __init__(self,
                 base_db: AsyncBaseDB,
                 chain: AsyncChain,
                 chaindb: AsyncChainDB,
                 chain_head_db: AsyncChainHeadDB,
                 chain_config: 'ChainConfig',
                 network_id: int,
                 vm_configuration: Tuple[Tuple[int, Type[BaseVM]], ...]) -> None:
        self.base_db = base_db
        self.chain = chain
        self.chaindb = chaindb
        self.chain_head_db = chain_head_db
        self.chain_config = chain_config
        self.network_id = network_id
        self.vm_configuration = vm_configuration
