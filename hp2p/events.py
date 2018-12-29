from typing import (
    Type,
)

from lahja import (
    BaseEvent,
    BaseRequestResponseEvent,
)

from eth_typing import Address

from helios.rlp_templates.hls import P2PBlock


class PeerCountResponse(BaseEvent):

    def __init__(self, peer_count: int) -> None:
        self.peer_count = peer_count


class PeerCountRequest(BaseRequestResponseEvent[PeerCountResponse]):

    @staticmethod
    def expected_response_type() -> Type[PeerCountResponse]:
        return PeerCountResponse

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
