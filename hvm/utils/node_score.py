from typing import TYPE_CHECKING
import rlp_cython as rlp
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



from hvm.utils.transactions import (
    extract_chain_id,
    extract_signature_v

)

if TYPE_CHECKING:
    from hvm.rlp.consensus import (
        NodeStakingScore
    )


EIP155_CHAIN_ID_OFFSET = 35
V_OFFSET = 27


# def get_message_from_node_staking_score(node_staking_score: 'NodeStakingScore', chain_id:int = None) -> bytes:
#     if chain_id is None:
#         chain_id = node_staking_score.chain_id
#
#     transaction_parts = rlp.decode(rlp.encode(node_staking_score), use_list=True)
#
#     transaction_parts_for_signature = transaction_parts[:-3] + [int_to_big_endian(chain_id), b'', b'']
#
#     message = rlp.encode(transaction_parts_for_signature)
#     return message


def create_node_staking_score_signature(node_staking_score: 'NodeStakingScore', private_key, chain_id):
    message = node_staking_score.get_message_for_signing(chain_id)
    signature = private_key.sign_msg(message)

    canonical_v, r, s = signature.vrs

    v = canonical_v + chain_id * 2 + EIP155_CHAIN_ID_OFFSET

    return v, r, s


def validate_node_staking_score_signature(node_staking_score: 'NodeStakingScore', return_sender = False) -> None:
    v = extract_signature_v(node_staking_score.v)


    canonical_v = v - 27
    vrs = (canonical_v, node_staking_score.r, node_staking_score.s)
    signature = keys.Signature(vrs=vrs)

    message = node_staking_score.get_message_for_signing()
    
    try:
        public_key = signature.recover_public_key_from_msg(message)
    except BadSignature as e:
        raise ValidationError("Bad Signature: {0}".format(str(e)))

    if not signature.verify_msg(message, public_key):
        raise ValidationError("Invalid Signature")

    if return_sender:
        return public_key.to_canonical_address()

#@lru_cache(maxsize=32)
def extract_node_staking_score_sender(node_staking_score: 'NodeStakingScore') -> bytes:

    v = extract_signature_v(node_staking_score.v)

    canonical_v = v - 27
    vrs = (canonical_v, node_staking_score.r, node_staking_score.s)
    signature = keys.Signature(vrs=vrs)

    message = node_staking_score.get_message_for_signing()
    
    public_key = signature.recover_public_key_from_msg(message)
    sender = public_key.to_canonical_address()
    return sender
