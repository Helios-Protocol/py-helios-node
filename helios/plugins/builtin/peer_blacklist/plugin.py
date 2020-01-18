import asyncio

from helios.extensibility import (
    BaseEvent,
    BaseAsyncStopPlugin,
)
from helios.plugins.builtin.peer_blacklist.peer_blacklist import PeerBlacklistHandler


class PeerBlacklistPlugin(BaseAsyncStopPlugin):

    handler: PeerBlacklistHandler = None

    @property
    def name(self) -> str:
        return "PeerBlacklistPlugin"

    def should_start(self) -> bool:
        return True

    def start(self) -> None:
        self.logger.info('PeerBlacklistPlugin started')
        self.handler = PeerBlacklistHandler(self.context.event_bus)
        asyncio.ensure_future(self.handler.run())

    async def stop(self) -> None:
        # This isn't really needed for the standard shutdown case as the PeerBlacklistPlugin will
        # automatically shutdown whenever the `CancelToken` it was chained with is triggered.
        # It may still be useful to stop the LightPeerChain Bridge plugin individually though.
        if self.handler.is_operational:
            await self.handler.cancel()
            self.logger.info("Successfully stopped PeerBlacklistPlugin")
