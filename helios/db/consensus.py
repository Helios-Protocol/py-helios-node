# Typeshed definitions for multiprocessing.managers is incomplete, so ignore them for now:
# https://github.com/python/typeshed/blob/85a788dbcaa5e9e9a62e55f15d44530cd28ba830/stdlib/3/multiprocessing/managers.pyi#L3
from multiprocessing.managers import (  # type: ignore
    BaseProxy,
)
from hvm.db.consensus import ConsensusDB

from helios.utils.mp import (
    async_method,
    sync_method,
)

class AsyncConsensusDB(ConsensusDB):
    pass
    
    

class ConsensusDBProxy(BaseProxy):

    # coro_get_historical_root_hashes = async_method('get_historical_root_hashes')
    #
    #
    save_health_request = sync_method('save_health_request')

    get_timestamp_of_last_health_request = sync_method('get_timestamp_of_last_health_request')