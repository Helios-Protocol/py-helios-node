from __future__ import absolute_import

import rlp

from cytoolz import (
    curry,
)

from eth_utils import (
    to_tuple,
)
from eth_utils import decode_hex
from hvm.exceptions import ValidationError


@to_tuple
def diff_rlp_object(left, right):
    if left != right:
        rlp_type = type(left)

        for field_name, field_type in rlp_type._meta.fields:
            left_value = getattr(left, field_name)
            right_value = getattr(right, field_name)
            if isinstance(field_type, type) and issubclass(field_type, rlp.Serializable):
                sub_diff = diff_rlp_object(left_value, right_value)
                for sub_field_name, sub_left_value, sub_right_value in sub_diff:
                    yield (
                        "{0}.{1}".format(field_name, sub_field_name),
                        sub_left_value,
                        sub_right_value,
                    )
            elif isinstance(field_type, (rlp.sedes.List, rlp.sedes.CountableList)):
                if tuple(left_value) != tuple(right_value):
                    yield (
                        field_name,
                        left_value,
                        right_value,
                    )
            elif left_value != right_value:
                yield (
                    field_name,
                    left_value,
                    right_value,
                )
            else:
                continue


@curry
def ensure_rlp_objects_are_equal(obj_a, obj_b, obj_a_name, obj_b_name):
    if obj_a == obj_b:
        return
    diff = diff_rlp_object(obj_a, obj_b)
    longest_field_name = max(len(field_name) for field_name, _, _ in diff)
    error_message = (
        "Mismatch between {obj_a_name} and {obj_b_name} on {0} fields:\n - {1}".format(
            len(diff),
            "\n - ".join(tuple(
                "{0}:\n    (actual)  : {1}\n    (expected): {2}".format(
                    field_name.ljust(longest_field_name, ' '),
                    actual,
                    expected,
                )
                for field_name, actual, expected
                in diff
            )),
            obj_a_name=obj_a_name,
            obj_b_name=obj_b_name,
        )
    )
    raise ValidationError(error_message)


ensure_imported_block_unchanged = ensure_rlp_objects_are_equal(
    obj_a_name="block",
    obj_b_name="imported block",
)

def make_mutable(value):
    if isinstance(value, tuple):
        return list(make_mutable(item) for item in value)
    else:
        return value
    
def convert_rlp_to_correct_class(wanted_class, given_object):

    parameter_names = list(dict(given_object._meta.fields).keys())

    dict_params = {}
    for parameter_name in parameter_names:
        dict_params[parameter_name] = getattr(given_object, parameter_name)

    new_object = wanted_class(**dict_params)
    return new_object

    #
    # parameters = []
    # for parameter_name in parameter_names:
    #     parameters.append(getattr(given_object, parameter_name))
    #
    # new_object = wanted_class(*parameters)
    # return new_object


# def convert_micro_block_dict_to_correct_types(block_dict):
#     '''
#     This is to deal with signed blocks coming in from RPC. They don't contain all of the same fields as a normal block
#     :param block_dict:
#     :return:
#     '''
#     block_dict['header']['parent_hash'] = decode_hex(block_dict['header']['parent_hash'])
#     block_dict['header']['transaction_root'] = decode_hex(block_dict['header']['transaction_root'])
#     block_dict['header']['receive_transaction_root'] = decode_hex(block_dict['header']['receive_transaction_root'])
#     block_dict['header']['extra_data'] = decode_hex(block_dict['header']['extra_data'])
#     block_dict['header']['block_number'] = int(block_dict['header']['block_number'], 16)
#     block_dict['header']['timestamp'] = int(block_dict['header']['timestamp'], 16)
#     block_dict['header']['v'] = int(block_dict['header']['v'], 16)
#     block_dict['header']['r'] = int(block_dict['header']['r'], 16)
#     block_dict['header']['s'] = int(block_dict['header']['s'], 16)
#
#     for i in range(len(block_dict['transactions'])):
#         block_dict['transactions'][i]['nonce'] = int(block_dict['transactions'][i]['nonce'], 16)
#         block_dict['transactions'][i]['gas_price'] = int(block_dict['transactions'][i]['gas_price'], 16)
#         block_dict['transactions'][i]['gas'] = int(block_dict['transactions'][i]['gas'], 16)
#         block_dict['transactions'][i]['value'] = int(block_dict['transactions'][i]['value'], 16)
#         block_dict['transactions'][i]['v'] = int(block_dict['transactions'][i]['v'], 16)
#         block_dict['transactions'][i]['r'] = int(block_dict['transactions'][i]['r'], 16)
#         block_dict['transactions'][i]['s'] = int(block_dict['transactions'][i]['s'], 16)
#
#         block_dict['transactions'][i]['to'] = decode_hex(block_dict['transactions'][i]['to'])
#         block_dict['transactions'][i]['data'] = decode_hex(block_dict['transactions'][i]['data'])
#
#     for i in range(len(block_dict['receive_transactions'])):
#         block_dict['receive_transactions'][i]['parent_block_hash'] = decode_hex(
#             block_dict['receive_transactions'][i]['parent_block_hash'])
#         block_dict['receive_transactions'][i]['transaction_hash'] = decode_hex(
#             block_dict['receive_transactions'][i]['transaction_hash'])
#
#     return block_dict
#
#