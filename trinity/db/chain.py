import asyncio
import logging

from multiprocessing.managers import (
    BaseProxy,
)


logger = logging.getLogger('trinity.DEBUG')


class ChainDBProxy(BaseProxy):
    def get_canonical_head(self):
        return self._callmethod('get_canonical_head')

    async def persist_header_to_db(self, header):
        loop = asyncio.get_event_loop()

        return await loop.run_in_executor(
            None,
            self._callmethod,
            'persist_header_to_db',
            (header,),
        )

    def header_exists(self, block_hash):
        return self._callmethod('header_exists', (block_hash,))

    def lookup_block_hash(self, block_number):
        return self._callmethod('lookup_block_hash', (block_number,))

    def get_block_header_by_hash(self, block_hash):
        return self._callmethod('get_block_header_by_hash', (block_hash,))

    def get_score(self, block_hash):
        return self._callmethod('get_score', (block_hash,))
