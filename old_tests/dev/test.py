import bisect
import time
import random
from itertools import groupby as itergroupby
from cytoolz import groupby
from hvm.utils.rlp import make_mutable

from sortedcontainers import SortedDict

unsorted_dict = {}
for i in range(10000):
    key = random.randint(1000000000,10000000000)
    val = random.randint(1000000000, 10000000000)
    unsorted_dict[key] = val

start_time = time.time()

sorted_dict = SortedDict(lambda x: int(x) * -1, unsorted_dict)

print("sorteddict took", format(time.time() - start_time))

start_time = time.time()
#sorted_list = [[key, unsorted_dict[key]] for key in sorted(unsorted_dict)]
{k: unsorted_dict[k] for k in sorted(unsorted_dict, key=lambda x: int(x) * -1)}

print("my thing took", format(time.time() - start_time))

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