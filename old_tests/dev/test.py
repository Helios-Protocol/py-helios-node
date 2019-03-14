import bisect
import time
import os
import random
import linecache
from itertools import groupby as itergroupby
from cytoolz import groupby
from hvm.utils.rlp import make_mutable
from hvm.constants import GENESIS_WALLET_ADDRESS
from hvm.vm.forks.helios_testnet.transactions import HeliosTestnetTransaction
from hvm.rlp.consensus import StakeRewardBundle, StakeRewardType2
from sortedcontainers import SortedDict
import rlp_cython as rlp
from eth_utils import to_hex
from msgpack_rlp import packb, unpackb

import tracemalloc

tracemalloc.start()


def get_top_memory_usage(snapshot, key_type='lineno', limit=3):
    snapshot = snapshot.filter_traces((
        tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
        tracemalloc.Filter(False, "<unknown>"),
    ))
    top_stats = snapshot.statistics(key_type)

    out = []
    print("Top %s lines" % limit)
    for index, stat in enumerate(top_stats[:limit], 1):
        frame = stat.traceback[0]
        # replace "/path/to/module/file.py" with "module/file.py"
        filename = os.sep.join(frame.filename.split(os.sep)[-2:])
        print("#%s: %s:%s: %.1f KiB"
                   % (index, filename, frame.lineno, stat.size / 1024))
        line = linecache.getline(frame.filename, frame.lineno).strip()
        if line:
            print('    %s' % line)

    other = top_stats[limit:]
    if other:
        size = sum(stat.size for stat in other)
        print("%s other: %.1f KiB" % (len(other), size / 1024))
    total = sum(stat.size for stat in top_stats)
    print("Total allocated size: %.1f KiB" % (total / 1024))


num = 0
test = [1234]*10000
while True:
    print(num)
    encoded = packb(test)
    decoded = unpackb(encoded, sedes=[1], use_list = True)
    if num % 50 == 0:
        snapshot = tracemalloc.take_snapshot()
        print(get_top_memory_usage(snapshot))
    num += 1




# test = []
# for i in range(100000):
#     test.append([i, random.randint(0,10000)])
#
# print(test)
#
# spacing = 100
#
# start_time = time.time()
# grouped = itergroupby(test, key = lambda x: int(x[0]/spacing)*spacing)
#
# grouped_sum
#
# print("itertoolz took", format(time.time() - start_time))
#
#
# # start_time = time.time()
# # grouped = groupby(key = lambda x: int(x[0]/spacing)*spacing, seq = test)
# #
# # # print(grouped)
# # # for index, group in grouped.items():
# # #     print(index)
# # #     print(list(group))
# #
# # print("cytoolz took", format(time.time() - start_time))