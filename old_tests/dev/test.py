from hvm.utils.hexadecimal import pad_hex
from eth_utils import remove_0x_prefix

import itertools
import time

start = time.time()
test = []
for i in range(1000):
    test.append(1)
end_time = time.time()
print("Took {}".format(end_time-start))
print(test)

start = time.time()
test = list(itertools.repeat(1,1000))
end_time = time.time()
print("Took {}".format(end_time-start))
print(test)


start = time.time()
test = [1]*1000
end_time = time.time()
print("Took {}".format(end_time-start))
print(test)


