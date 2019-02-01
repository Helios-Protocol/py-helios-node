import bisect
import time
import random
from itertools import groupby as itergroupby
from cytoolz import groupby
from hvm.utils.rlp import make_mutable
from hvm.constants import GENESIS_WALLET_ADDRESS
from hvm.vm.forks.helios_testnet.transactions import HeliosTestnetTransaction
from hvm.rlp.consensus import StakeRewardBundle, StakeRewardType2
from sortedcontainers import SortedDict
import rlp_cython as rlp
from eth_utils import to_hex

def underscore_to_camel_case(input_string:str) -> str:
    if isinstance(input_string,str):
        pieces = input_string.split('_')
        camel_case_string = pieces[0]
        for i in range(1,len(pieces)):
            camel_case_string += pieces[i].capitalize()
        return camel_case_string
    else:
        return ''

def all_rlp_fields_to_dict_camel_case(rlp_object):
    #It is either rlp.Serializable or a list
    if isinstance(rlp_object, rlp.Serializable):
        dict_to_return = {}
        # add all of the fields in camelcase
        for i in range(len(rlp_object._meta.field_names)):
            field_name = rlp_object._meta.field_names[i]
            key = underscore_to_camel_case(field_name)
            raw_val = getattr(rlp_object, field_name)
            if isinstance(raw_val, rlp.Serializable) or isinstance(raw_val, list) or isinstance(raw_val, tuple):
                val=all_rlp_fields_to_dict_camel_case(raw_val)
            else:
                val = to_hex(raw_val)

            dict_to_return[key] = val
        return dict_to_return
    else:
        list_to_return = []
        for i in range(len(rlp_object)):
            raw_val = rlp_object[i]
            if isinstance(raw_val, rlp.Serializable) or isinstance(raw_val, list) or isinstance(raw_val, tuple):
                val = all_rlp_fields_to_dict_camel_case(raw_val)
            else:
                val = to_hex(raw_val)
            list_to_return.append(val)
        return list_to_return




test_reward_bundle = StakeRewardBundle()

final_dict = all_rlp_fields_to_dict_camel_case(test_reward_bundle)
print(final_dict)

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