import operator
import random
from typing import (
    Dict,
    List,
    NamedTuple,
    Tuple,
    Type,
    TYPE_CHECKING
)

from eth_typing import (
    BlockNumber,
    Hash32,
)

from eth_utils.toolz import groupby

from hvm.constants import GENESIS_BLOCK_NUMBER
from hvm.rlp.headers import BlockHeader
from hvm.vm.base import BaseVM

from hp2p.exceptions import NoConnectedPeers
from hp2p.kademlia import Node
from hp2p.peer import (
    BasePeer,
    BasePeerFactory,
    BasePeerPool,
)

from helios.db.chain_head import AsyncChainHeadDB
from helios.db.chain import AsyncChainDB
from helios.chains.coro import AsyncChain

from .context import ChainContext

if TYPE_CHECKING:
    from helios.config import ChainConfig

# class ChainInfo(NamedTuple):
#     block_number: BlockNumber
#     block_hash: Hash32
#     total_difficulty: int
#     genesis_hash: Hash32

class ChainInfo:
    def __init__(self, node_type, genesis_block_hash):
        self.node_type=node_type
        self.genesis_block_hash = genesis_block_hash

class BaseChainPeer(BasePeer):
    #boot_manager_class = DAOCheckBootManager
    context: ChainContext

    head_td: int = None
    head_hash: Hash32 = None

    @property
    def chaindb(self) -> AsyncChainDB:
        return self.context.chaindb

    @property
    def chains(self) -> List[AsyncChain]:
        return self.context.chains

    @property
    def chain_head_db(self) -> AsyncChainHeadDB:
        return self.context.chain_head_db

    @property
    def chain_config(self) -> 'ChainConfig':
        return self.context.chain_config

    @property
    def network_id(self) -> int:
        return self.context.network_id

    @property
    def vm_configuration(self) -> Tuple[Tuple[int, Type[BaseVM]], ...]:
        return self.context.vm_configuration

    @property
    async def genesis(self) -> BlockHeader:
        genesis_hash = await self.wait(
            self.chaindb.coro_get_canonical_block_hash(BlockNumber(GENESIS_BLOCK_NUMBER)))
        return await self.wait(self.chaindb.coro_get_block_header_by_hash(genesis_hash))

    @property
    async def _local_chain_info(self) -> 'ChainInfo':
        node_type = self.chain_config.node_type
        genesis_block_hash = self.chains[0].get_genesis_block_hash()

        return ChainInfo(
            node_type=node_type,
            genesis_block_hash=genesis_block_hash
        )


class BaseChainPeerFactory(BasePeerFactory):
    context: ChainContext


class BaseChainPeerPool(BasePeerPool):
    connected_nodes: Dict[Node, BaseChainPeer]  # type: ignore

    @property
    def highest_td_peer(self) -> BaseChainPeer:
        peers = tuple(self.connected_nodes.values())
        if not peers:
            raise NoConnectedPeers()
        peers_by_td = groupby(operator.attrgetter('head_td'), peers)
        max_td = max(peers_by_td.keys())
        return random.choice(peers_by_td[max_td])

    def get_peers(self, min_stake: int = 0) -> List[BaseChainPeer]:
        # TODO: Consider turning this into a method that returns an AsyncIterator, to make it
        # harder for callsites to get a list of peers while making blocking calls, as those peers
        # might disconnect in the meantime.
        if min_stake == 0:
            #if we have no minimum stake, return all peers, even ones where we don't know the stake.
            peers = tuple(self.connected_nodes.values())
            return peers
        else:
            peers = tuple(self.connected_nodes.values())
            peers_with_stake = [peer for peer in peers if peer._stake is not None]
            return [peer for peer in peers_with_stake if peer._stake >= min_stake]

