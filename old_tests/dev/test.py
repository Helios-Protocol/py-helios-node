from abc import (
    abstractmethod
)

test = [(1,2),(3,4)]
print(*test)


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