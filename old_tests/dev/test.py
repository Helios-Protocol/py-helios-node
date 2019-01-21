import bisect
import time
import random
from itertools import groupby as itergroupby
from cytoolz import groupby
from hvm.utils.rlp import make_mutable


class test_class:
    pass

filler_list = [1,2,3,4,5,6,7]

buckets = []

for i in range(5):
    test_list = []
    test_list_2 = []

    test_list.append(filler_list[i])
    test_list_2.append(test_list)
    bucket = test_class()
    bucket.test_list = test_list
    bucket.test_list_2 = test_list
    buckets.append(bucket)


print([bucket.test_list for bucket in buckets])
print([bucket.test_list_2 for bucket in buckets])



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