from cytoolz import (
    identity,
)
from eth_typing import Hash32, Address

from eth_utils import (
    decode_hex,
    encode_hex,
    int_to_big_endian,
    is_integer,
    big_endian_to_int,
    to_wei,
    from_wei,
)

import time
from hvm.rlp.transactions import BaseReceiveTransaction
from helios.exceptions import BaseRPCError
from helios.rpc.constants import MAX_ALLOWED_AGE_OF_NEW_RPC_BLOCK
from helios.rpc.format import (
    block_to_dict,
    header_to_dict,
    format_params,
    to_int_if_hex,
    transaction_to_dict,
    receipt_to_dict,
    receive_transactions_to_dict,
    decode_hex_if_str,
    receive_transaction_to_dict, connected_nodes_to_dict)
import rlp_cython as rlp
from helios.sync.common.constants import FULLY_SYNCED_STAGE_ID

from hvm.exceptions import (
    CanonicalHeadNotFound,
    HeaderNotFound,
    TransactionNotFound,
)
from hvm.utils.blocks import does_block_meet_min_gas_price, get_block_average_transaction_gas_price

from hvm.types import Timestamp

#from hp2p.chain import NewBlockQueueItem

from eth_utils import is_hex_address, to_checksum_address

# Tell mypy to ignore this import as a workaround for https://github.com/python/mypy/issues/4049
from helios.rpc.modules import (  # type: ignore
    RPCModule,
)

from hvm.constants import (
    TIME_BETWEEN_HEAD_HASH_SAVE,
    NUMBER_OF_HEAD_HASH_TO_SAVE,
    BLOCK_TIMESTAMP_FUTURE_ALLOWANCE)

from hvm.utils.headers import (
    compute_gas_limit,
)
from hvm.chains.base import BaseChain

from helios.rlp_templates.hls import P2PBlock

import asyncio

from typing import cast

from hp2p.events import NewBlockEvent, StakeFromBootnodeRequest, CurrentSyncStageRequest, \
    CurrentSyncingParametersRequest, GetConnectedNodesRequest

from hvm.rlp.consensus import StakeRewardBundle
from hvm.vm.forks.helios_testnet.blocks import HeliosMicroBlock

class Dev(RPCModule):
    '''
    All the methods defined by JSON-RPC API, starting with "hls_"...

    Any attribute without an underscore is publicly accessible.
    '''

    #
    # Tools
    #

    @format_params(to_int_if_hex)
    async def delayedResponse(self, wait_time) -> bool:
        """
        For testing async/sync responses over websockets and http
        """
        await asyncio.sleep(wait_time)
        return True

