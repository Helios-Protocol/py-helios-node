import bisect
import time
import random

test_timestamp_value_list = []
for i in range(1000):
    number = random.randint(100, 10000000)
    test_timestamp_value_list.append([number, 'sadfsadfasdf'])



print(test_timestamp_value_list)
start_timestamp = time.time()
for i in range(1000):
    #test_timestamp_value_list = sorted(test_timestamp_value_list)
    test_timestamp_value_list.sort()
    timestamps = [x[0] for x in test_timestamp_value_list]

    index = bisect.bisect_right(timestamps, 100000)-1

    what = test_timestamp_value_list[index]

print(what)
print(time.time()-start_timestamp)

