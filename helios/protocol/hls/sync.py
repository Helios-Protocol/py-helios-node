from hp2p.constants import ADDITIVE_SYNC_MODE_CUTOFF, SYNC_STAGE_4_START_OFFSET
from hvm.types import Timestamp
import time
from hvm.constants import (
    NUMBER_OF_HEAD_HASH_TO_SAVE,
    TIME_BETWEEN_HEAD_HASH_SAVE,
)
from helios.sync.common.constants import (
    FAST_SYNC_STAGE_ID,
    CONSENSUS_MATCH_SYNC_STAGE_ID,
    ADDITIVE_SYNC_STAGE_ID,
    FULLY_SYNCED_STAGE_ID,
)



def get_earliest_required_time_for_min_gas_system() -> Timestamp:
    '''
    Blocks are only checked against the minimum allowed gas price for sync stage 3, 4
    :return:
    '''
    last_allowed_hist_root_hash = int(time.time()) - ADDITIVE_SYNC_MODE_CUTOFF
    chronological_block_window_for_this_root_hash = last_allowed_hist_root_hash-TIME_BETWEEN_HEAD_HASH_SAVE
    return chronological_block_window_for_this_root_hash

def get_max_centiseconds_of_hist_min_gas_price_to_keep():
    '''
    We want to keep significantly more than needed to cover our bases
    :return:
    '''
    min_required = int((int(time.time()) - get_earliest_required_time_for_min_gas_system())/100)+100
    safe_amount = min_required + 100
    return safe_amount

def get_sync_stage_for_historical_root_hash_timestamp(timestamp: Timestamp) -> int:
    '''
    This is the sync stage to get to this historical root hash timestamp.
    This means that we have to look at the blocks in the previous chronological window
    to get here. So it is this timestamp - TIME_BETWEEN_HEAD_HASH_SAVE that must fit into the
    correct time window.
    ''
    There are 4 stages of syncing that depend on how old the block is.
    1) Fast sync (Oldest)
    2) Consensus match sync
    3) Additive sync
    4) New block propagating syncing (Newest)
    :param timestamp:
    :return:
    '''
    # the chronological block window corresponding to the historical block hash is up to TIME_BETWEEN_HEAD_HASH_SAVE behind.
    # |+++++++|+++++++|+++++++|+++++++|+++++++|+++++++|+++++++|
    # RH  B-> RH  B-> RH                             time ->


    last_finished_window = int(time.time() / TIME_BETWEEN_HEAD_HASH_SAVE) * TIME_BETWEEN_HEAD_HASH_SAVE
    current_window = last_finished_window + TIME_BETWEEN_HEAD_HASH_SAVE

    if timestamp < current_window - NUMBER_OF_HEAD_HASH_TO_SAVE * TIME_BETWEEN_HEAD_HASH_SAVE + TIME_BETWEEN_HEAD_HASH_SAVE:
        return FAST_SYNC_STAGE_ID
    elif timestamp < int(time.time()) - ADDITIVE_SYNC_MODE_CUTOFF:
        return CONSENSUS_MATCH_SYNC_STAGE_ID
    elif timestamp < int(time.time()) - SYNC_STAGE_4_START_OFFSET:
        return ADDITIVE_SYNC_STAGE_ID
    else:
        return FULLY_SYNCED_STAGE_ID


def get_sync_stage_for_chronological_block_window_timestamp(timestamp: Timestamp) -> int:
    historical_root_hash_for_this_block = timestamp + TIME_BETWEEN_HEAD_HASH_SAVE
    return get_sync_stage_for_historical_root_hash_timestamp(historical_root_hash_for_this_block)


def get_sync_stage_for_block_timestamp(timestamp: Timestamp) -> int:
    chronological_block_window_for_this_block = int(timestamp/TIME_BETWEEN_HEAD_HASH_SAVE)*TIME_BETWEEN_HEAD_HASH_SAVE
    return get_sync_stage_for_chronological_block_window_timestamp(chronological_block_window_for_this_block)

