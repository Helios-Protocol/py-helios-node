from typing import Type

from lahja import (
    BaseEvent,
    BaseRequestResponseEvent,
)


class IsPeerOnBlacklistResponse(BaseEvent):

    def __init__(self, is_peer_on_blacklist: bool) -> None:
        self.is_peer_on_blacklist = is_peer_on_blacklist

class IsPeerOnBlacklistRequest(BaseRequestResponseEvent[IsPeerOnBlacklistResponse]):

    def __init__(self, node_pubkey: bytes) -> None:
        self.node_pubkey = node_pubkey

    @staticmethod
    def expected_response_type() -> Type[IsPeerOnBlacklistResponse]:
        return IsPeerOnBlacklistResponse

class AddPeerToBlacklistRequest(BaseEvent):

    def __init__(self, node_pubkey: bytes) -> None:
        self.node_pubkey = node_pubkey

class RemovePeerFromBlacklistRequest(BaseEvent):

    def __init__(self, node_pubkey: bytes) -> None:
        self.node_pubkey = node_pubkey