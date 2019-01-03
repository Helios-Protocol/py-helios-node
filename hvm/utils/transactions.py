
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

from hvm.rlp.transactions import (
    BaseTransaction,
    BaseReceiveTransaction
)


EIP155_CHAIN_ID_OFFSET = 35
V_OFFSET = 27


def is_eip_155_signed_transaction(transaction: BaseTransaction) -> bool:
    if transaction.v >= EIP155_CHAIN_ID_OFFSET:
        return True
    else:
        return False


def extract_chain_id(v: int) -> int:
    if is_even(v):
        chain_id = (v - EIP155_CHAIN_ID_OFFSET - 1) // 2
    else:
        chain_id = (v - EIP155_CHAIN_ID_OFFSET) // 2

    if chain_id < 0:
        raise ValidationError('Cannot extract chain id from object. Invalid signature or chain id.')

    return chain_id


def extract_signature_v(v: int) -> int:
    if is_even(v):
        return V_OFFSET + 1
    else:
        return V_OFFSET


# def get_message_from_transaction(transaction: Union[BaseTransaction, BaseReceiveTransaction], chain_id:int = None) -> bytes:
#     if chain_id is None:
#         chain_id = transaction.chain_id
#
#     transaction_parts = rlp.decode(rlp.encode(transaction), use_list=True)
#
#     transaction_parts_for_signature = transaction_parts[:-3] + [int_to_big_endian(chain_id), b'', b'']
#
#     message = rlp.encode(transaction_parts_for_signature)
#     return message

#require chain id
def create_transaction_signature(transaction: Union[BaseTransaction, BaseReceiveTransaction], private_key, chain_id):
    message = transaction.get_message_for_signing(chain_id)
    signature = private_key.sign_msg(message)

    canonical_v, r, s = signature.vrs

    v = canonical_v + chain_id * 2 + EIP155_CHAIN_ID_OFFSET

    return v, r, s


def validate_transaction_signature(transaction: Union[BaseTransaction, BaseReceiveTransaction], return_sender = False) -> None:

    v = extract_signature_v(transaction.v)

    canonical_v = v - 27
    vrs = (canonical_v, transaction.r, transaction.s)
    signature = keys.Signature(vrs=vrs)

    message = transaction.get_message_for_signing()
    
    try:
        public_key = signature.recover_public_key_from_msg(message)
    except BadSignature as e:
        raise ValidationError("Bad Signature: {0}".format(str(e)))

    if not signature.verify_msg(message, public_key):
        raise ValidationError("Invalid Signature")

    if return_sender:
        return public_key.to_canonical_address()

#@lru_cache(maxsize=32)
def extract_transaction_sender(transaction: Union[BaseTransaction, BaseReceiveTransaction]) -> bytes:
    v = extract_signature_v(transaction.v)

    canonical_v = v - 27
    vrs = (canonical_v, transaction.r, transaction.s)
    signature = keys.Signature(vrs=vrs)

    message = transaction.get_message_for_signing()
    
    public_key = signature.recover_public_key_from_msg(message)
    sender = public_key.to_canonical_address()
    return sender
