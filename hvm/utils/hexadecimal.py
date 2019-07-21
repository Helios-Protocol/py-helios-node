from __future__ import unicode_literals

import codecs

from eth_utils import remove_0x_prefix

def encode_hex(value):
    return '0x' + codecs.decode(codecs.encode(value, 'hex'), 'utf8')


def decode_hex(value):
    _, _, hex_part = value.rpartition('x')
    return codecs.decode(hex_part, 'hex')

def pad_hex(value, length_in_bytes):
    prefix_removed_value = remove_0x_prefix(value)
    num_pad_required = length_in_bytes * 2 - len(prefix_removed_value)
    padding = '0' * num_pad_required
    result = '0x' + padding + prefix_removed_value
    return result
