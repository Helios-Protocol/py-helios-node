from hvm.utils.hexadecimal import pad_hex
from eth_utils import remove_0x_prefix
value = '0x12ff28'

test = [1,2,3,5,6,8,7,2,3,87,3,2]
test.sort()

while test[0] < 3:
    del(test[0])

print(test)
