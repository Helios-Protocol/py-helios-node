from .keystore import (
    make_keystore_json,
    check_keystore_json,
    decode_keystore_json,        
)

from eth_keys import keys

from eth_keys.datatypes import(
        BaseKey,
        PublicKey,
        PrivateKey
)

#for testing purposes we will just have the primary private key hardcoded
#TODO: save to encrypted json file
primary_private_key = b'p.Oids\xedb\xa3\x93\xc5\xad\xb9\x8d\x92\x94\x00\x06\xb9\x82\xde\xb9\xbdBg\\\x82\xd4\x90W\xd0\xd5'

def get_primary_node_private_helios_key():
    return keys.PrivateKey(primary_private_key)