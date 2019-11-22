from typing import (
    Type,
    Dict,
    Any,
    TYPE_CHECKING
)

from dataclasses import (
    dataclass,
)

from lahja import (
    BaseEvent,
    BaseRequestResponseEvent,
)

from eth_typing import Address
from helios.protocol.common.datastructures import SyncParameters

from helios.rlp_templates.hls import P2PBlock
if TYPE_CHECKING:
    from helios.protocol.common.datastructures import ConnectedNodesInfo

class AverageNetworkMinGasPriceResponse(BaseEvent):

    def __init__(self, min_gas_price: int) -> None:
        self.min_gas_price = min_gas_price


class AverageNetworkMinGasPriceRequest(BaseRequestResponseEvent[AverageNetworkMinGasPriceResponse]):

    @staticmethod
    def expected_response_type() -> Type[AverageNetworkMinGasPriceResponse]:
        return AverageNetworkMinGasPriceResponse

class BlockImportQueueLengthResponse(BaseEvent):

    def __init__(self, queue_length: int) -> None:
        self.queue_length = queue_length


class BlockImportQueueLengthRequest(BaseRequestResponseEvent[BlockImportQueueLengthResponse]):

    @staticmethod
    def expected_response_type() -> Type[BlockImportQueueLengthResponse]:
        return BlockImportQueueLengthResponse

class PeerCountResponse(BaseEvent):

    def __init__(self, peer_count: int) -> None:
        self.peer_count = peer_count


class PeerCountRequest(BaseRequestResponseEvent[PeerCountResponse]):

    @staticmethod
    def expected_response_type() -> Type[PeerCountResponse]:
        return PeerCountResponse

class GetConnectedNodesResponse(BaseEvent):

    def __init__(self, connected_nodes: 'ConnectedNodesInfo') -> None:
        self.connected_nodes = connected_nodes


class GetConnectedNodesRequest(BaseRequestResponseEvent[GetConnectedNodesResponse]):

    @staticmethod
    def expected_response_type() -> Type[GetConnectedNodesResponse]:
        return GetConnectedNodesResponse

class CurrentSyncingParametersResponse(BaseEvent):

    def __init__(self, current_syncing_parameters: SyncParameters) -> None:
        self.current_syncing_parameters = current_syncing_parameters


class CurrentSyncingParametersRequest(BaseRequestResponseEvent[CurrentSyncingParametersResponse]):

    @staticmethod
    def expected_response_type() -> Type[CurrentSyncingParametersResponse]:
        return CurrentSyncingParametersResponse


class StakeFromBootnodeResponse(BaseEvent):

    def __init__(self, peer_stake_from_bootstrap_node: Dict[Any,Any]) -> None:
        self.peer_stake_from_bootstrap_node = peer_stake_from_bootstrap_node

class StakeFromBootnodeRequest(BaseRequestResponseEvent[StakeFromBootnodeResponse]):

    @staticmethod
    def expected_response_type() -> Type[StakeFromBootnodeResponse]:
        return StakeFromBootnodeResponse

class CurrentSyncStageResponse(BaseEvent):

    def __init__(self, sync_stage: int) -> None:
        self.sync_stage = sync_stage

class CurrentSyncStageRequest(BaseRequestResponseEvent[CurrentSyncStageResponse]):

    @staticmethod
    def expected_response_type() -> Type[CurrentSyncStageResponse]:
        return CurrentSyncStageResponse


class NoResponse(BaseEvent):

    def __init__(self) -> None:
        pass

class NewBlockEvent(BaseRequestResponseEvent[NoResponse]):

    def __init__(self, block:P2PBlock, only_propogate_to_network: bool= False, from_rpc:bool  = False) -> None:
        self.block = block
        self.only_propogate_to_network = only_propogate_to_network
        self.from_rpc = from_rpc

    @staticmethod
    def expected_response_type() -> Type[NoResponse]:
        return NoResponse

