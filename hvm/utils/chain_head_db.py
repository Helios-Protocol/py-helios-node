from hvm.constants import TIME_BETWEEN_HEAD_HASH_SAVE
import time

def round_down_to_nearest_historical_window(number: int) -> int:
    return int(int(number/TIME_BETWEEN_HEAD_HASH_SAVE)*TIME_BETWEEN_HEAD_HASH_SAVE)