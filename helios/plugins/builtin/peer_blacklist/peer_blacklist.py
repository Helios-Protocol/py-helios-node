import asyncio
import json
import logging
import pathlib
from typing import (
    Any,
    Callable,
    Tuple,
    Type)

from cytoolz import curry

from cancel_token import (
    CancelToken,
    OperationCancelled,
)
from eth_utils import to_bytes

from helios.plugins.builtin.peer_blacklist.events import AddPeerToBlacklistRequest, RemovePeerFromBlacklistRequest, \
    IsPeerOnBlacklistRequest, IsPeerOnBlacklistResponse
from hp2p.service import (
    BaseService,
)

from helios.rpc.main import (
    RPCServer,
)
from hvm.db.backends.memory import MemoryDB

from lahja import (
    BaseEvent,
    BaseRequestResponseEvent,
    Endpoint,
)


class PeerBlacklistHandler(BaseService):

    def __init__(
            self,
            event_bus: Endpoint,
            token: CancelToken = None,
            loop: asyncio.AbstractEventLoop = None) -> None:
        super().__init__(token=token, loop=loop)
        self.db = MemoryDB()
        self.event_bus = event_bus

    async def _run(self) -> None:
        self.logger.info("Running PeerBlacklistHandler")

        self.run_daemon_task(self.handle_add_peer_to_blacklist_requests())
        self.run_daemon_task(self.handle_remove_peer_from_blacklist_requests())
        self.run_daemon_task(self.handle_is_peer_on_blacklist_requests())
        await self.cancel_token.wait()

    async def handle_add_peer_to_blacklist_requests(self) -> None:
        async for event in self.event_bus.stream(AddPeerToBlacklistRequest):
            node_pubkey = event.node_pubkey
            #self.logger.debug("Adding peer {} to blacklist".format(node_pubkey))
            self.db[node_pubkey] = to_bytes(True)

    async def handle_remove_peer_from_blacklist_requests(self) -> None:
        async for event in self.event_bus.stream(RemovePeerFromBlacklistRequest):
            node_pubkey = event.node_pubkey
            #self.logger.debug("Removing peer {} from blacklist".format(node_pubkey))
            try:
                del self.db[node_pubkey]
            except KeyError:
                pass

    async def handle_is_peer_on_blacklist_requests(self) -> None:
        async for event in self.event_bus.stream(IsPeerOnBlacklistRequest):
            node_pubkey = event.node_pubkey
            if node_pubkey in self.db:
                is_peer_on_blacklist = True
            else:
                is_peer_on_blacklist = False

            #self.logger.debug("Checking that peer {} is in blacklist. is_peer_on_blacklist = {}".format(node_pubkey, is_peer_on_blacklist))
            self.event_bus.broadcast(
                event.expected_response_type()(is_peer_on_blacklist),
                event.broadcast_config()
            )


