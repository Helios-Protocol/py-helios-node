
import rlp
from functools import lru_cache
from eth_keys import keys
from eth_keys.exceptions import (
    BadSignature,
)

from hvm.exceptions import (
    ValidationError,
)
from hvm.utils.numeric import (
    is_even,
    int_to_big_endian,
)
from typing import Union

from hvm.rlp.consensus import (
    NodeStakingScore
)

from hvm.utils.transactions import (
    extract_chain_id,
    extract_signature_v

)


EIP155_CHAIN_ID_OFFSET = 35
V_OFFSET = 27



def create_node_staking_score_signature(node_staking_score: NodeStakingScore, private_key, chain_id):
    transaction_parts = rlp.decode(rlp.encode(node_staking_score), use_list = True)

    transaction_parts_for_signature = transaction_parts[:-3] + [int_to_big_endian(chain_id), b'', b'']

    message = rlp.encode(transaction_parts_for_signature)
    signature = private_key.sign_msg(message)

    canonical_v, r, s = signature.vrs

    v = canonical_v + chain_id * 2 + EIP155_CHAIN_ID_OFFSET

    return v, r, s


def validate_node_staking_score_signature(node_staking_score: NodeStakingScore, return_sender = False) -> None:
    v = extract_signature_v(node_staking_score.v)


    canonical_v = v - 27
    vrs = (canonical_v, node_staking_score.r, node_staking_score.s)
    signature = keys.Signature(vrs=vrs)
    
    transaction_parts = rlp.decode(rlp.encode(node_staking_score), use_list = True)
    transaction_parts_for_signature = (
        transaction_parts[:-3] + [int_to_big_endian(node_staking_score.chain_id), b'', b'']
    )
    message = rlp.encode(transaction_parts_for_signature)
    
    try:
        public_key = signature.recover_public_key_from_msg(message)
    except BadSignature as e:
        raise ValidationError("Bad Signature: {0}".format(str(e)))

    if not signature.verify_msg(message, public_key):
        raise ValidationError("Invalid Signature")

    if return_sender:
        return public_key.to_canonical_address()

#@lru_cache(maxsize=32)
def extract_node_staking_score_sender(node_staking_score: NodeStakingScore) -> bytes:

    v = extract_signature_v(node_staking_score.v)

    canonical_v = v - 27
    vrs = (canonical_v, node_staking_score.r, node_staking_score.s)
    signature = keys.Signature(vrs=vrs)
    
    transaction_parts = rlp.decode(rlp.encode(node_staking_score))
    transaction_parts_for_signature = (
        transaction_parts[:-3] + [int_to_big_endian(node_staking_score.chain_id), b'', b'']
    )
    message = rlp.encode(transaction_parts_for_signature)
    
    public_key = signature.recover_public_key_from_msg(message)
    sender = public_key.to_canonical_address()
    return sender
