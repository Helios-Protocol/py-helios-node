from typing import (
    Tuple,
    Type,
    TYPE_CHECKING,
    List,
)

from hvm.vm.base import BaseVM

from hp2p.peer import BasePeerContext

from helios.db.base import AsyncBaseDB
from helios.db.chain import AsyncChainDB
from helios.db.chain_head import AsyncChainHeadDB
from helios.db.consensus import AsyncConsensusDB
from helios.chains.coro import AsyncChain

if TYPE_CHECKING:
    from helios.config import ChainConfig


class ChainContext(BasePeerContext):
    def __init__(self,
                 base_db: AsyncBaseDB,
                 chains: List[AsyncChain],
                 chaindb: AsyncChainDB,
                 chain_head_db: AsyncChainHeadDB,
                 consensus_db: AsyncConsensusDB,
                 chain_config: 'ChainConfig',
                 network_id: int,
                 vm_configuration: Tuple[Tuple[int, Type[BaseVM]], ...]) -> None:
        self.base_db = base_db
        self.chains = chains
        self.chaindb = chaindb
        self.chain_head_db = chain_head_db
        self.consensus_db = consensus_db
        self.chain_config = chain_config
        self.network_id = network_id
        self.vm_configuration = vm_configuration
