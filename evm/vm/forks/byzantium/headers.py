from evm.validation import (
    validate_gt,
    validate_header_params_for_configuration,
)
from evm.vm.forks.homestead.headers import (
    create_homestead_header_from_parent,
)


def compute_byzantium_difficulty(parent_header, num_uncles, timestamp):
    """
    https://github.com/ethereum/EIPs/issues/100
    TODO: figure out how to know about uncles in this context...
    """
    parent_tstamp = parent_header.timestamp
    validate_gt(timestamp, parent_tstamp, title="Header.timestamp")
    offset = parent_header.difficulty // DIFFICULTY_ADJUSTMENT_DENOMINATOR

    sign = max(
        1 - (timestamp - parent_tstamp) // HOMESTEAD_DIFF_ADJUSTMENT_CUTOFF,
        -99)
    adj_factor = max(
        (2 if len(parent.uncles) else 1) - ((timestamp - parent.timestamp) // 9),
        -99)

    difficulty = int(max(
        parent_header.difficulty + offset * sign,
        min(parent_header.difficulty, DIFFICULTY_MINIMUM)))
    num_bomb_periods = (
        (parent_header.block_number + 1) // BOMB_EXPONENTIAL_PERIOD
    ) - BOMB_EXPONENTIAL_FREE_PERIODS
    if num_bomb_periods >= 0:
        return max(difficulty + 2**num_bomb_periods, DIFFICULTY_MINIMUM)
    else:
        return difficulty


def create_byzantium_header_from_parent(vm, parent_header, **header_params):
    if 'difficulty' not in header_params:
        header_params.setdefault('timestamp', parent_header.timestamp + 1)

        parent_uncles = vm.chaindb.get_block_uncles(parent_header.uncles_hash)
        header_params['difficulty'] = compute_byzantium_difficulty(
            parent_header=parent_header,
            num_uncles=len(parent_uncles),
            timestamp=header_params['timestamp'],
        )
    # TODO
    pass
