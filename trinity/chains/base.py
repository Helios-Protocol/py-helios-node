# Typeshed definitions for multiprocessing.managers is incomplete, so ignore them for now:
# https://github.com/python/typeshed/blob/85a788dbcaa5e9e9a62e55f15d44530cd28ba830/stdlib/3/multiprocessing/managers.pyi#L3
from multiprocessing.managers import (  # type: ignore
    BaseProxy,
)

from trinity.utils.mp import (
    async_method,
    sync_method,
)

class ChainProxy(BaseProxy):
    coro_import_block = async_method('import_block')
    coro_get_block_stake_from_children = async_method('get_block_stake_from_children')

    import_block = sync_method('import_block')
    get_block_stake_from_children = sync_method('get_block_stake_from_children')
