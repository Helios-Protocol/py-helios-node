from multiprocessing.managers import (
    BaseManager,
)
import pathlib

from helios.chains import (
    ChainProxy,
)
from helios.db.chain import ChainDBProxy
from helios.db.chain_head import ChainHeadDBProxy
from helios.db.base import DBProxy
from helios.db.consensus import ConsensusDBProxy


def create_chain_manager(ipc_path: pathlib.Path) -> BaseManager:
    """
    We're still using 'str' here on param ipc_path because an issue with
    multi-processing not being able to interpret 'Path' objects correctly
    """
    class ChainManager(BaseManager):
        pass

    # Typeshed definitions for multiprocessing.managers is incomplete, so ignore them for now:
    # https://github.com/python/typeshed/blob/85a788dbcaa5e9e9a62e55f15d44530cd28ba830/stdlib/3/multiprocessing/managers.pyi#L3

    ChainManager.register('get_chain', proxytype=ChainProxy)  # type: ignore

    manager = ChainManager(address=str(ipc_path))  # type: ignore
    return manager
