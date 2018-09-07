
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
        return (v - EIP155_CHAIN_ID_OFFSET - 1) // 2
    else:
        return (v - EIP155_CHAIN_ID_OFFSET) // 2


def extract_signature_v(v: int) -> int:
    if is_even(v):
        return V_OFFSET + 1
    else:
        return V_OFFSET


#require chain id
def create_transaction_signature(transaction: Union[BaseTransaction, BaseReceiveTransaction], private_key, chain_id):
    transaction_parts = rlp.decode(rlp.encode(transaction))
    transaction_parts_for_signature = (
        transaction_parts[:-3] + [int_to_big_endian(chain_id), b'', b'']
    )
    message = rlp.encode(transaction_parts_for_signature)
    signature = private_key.sign_msg(message)

    canonical_v, r, s = signature.vrs

    v = canonical_v + chain_id * 2 + EIP155_CHAIN_ID_OFFSET

    return v, r, s


def validate_transaction_signature(transaction: Union[BaseTransaction, BaseReceiveTransaction], return_sender = False) -> None:
    if is_eip_155_signed_transaction(transaction):
        v = extract_signature_v(transaction.v)
    else:
        v = transaction.v

    canonical_v = v - 27
    vrs = (canonical_v, transaction.r, transaction.s)
    signature = keys.Signature(vrs=vrs)
    
    transaction_parts = rlp.decode(rlp.encode(transaction))
    transaction_parts_for_signature = (
        transaction_parts[:-3] + [int_to_big_endian(transaction.chain_id), b'', b'']
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
def extract_transaction_sender(transaction: Union[BaseTransaction, BaseReceiveTransaction]) -> bytes:
    if is_eip_155_signed_transaction(transaction):
        v = extract_signature_v(transaction.v)
    else:
        v = transaction.v

    canonical_v = v - 27
    vrs = (canonical_v, transaction.r, transaction.s)
    signature = keys.Signature(vrs=vrs)
    
    transaction_parts = rlp.decode(rlp.encode(transaction))
    transaction_parts_for_signature = (
        transaction_parts[:-3] + [int_to_big_endian(transaction.chain_id), b'', b'']
    )
    message = rlp.encode(transaction_parts_for_signature)
    
    public_key = signature.recover_public_key_from_msg(message)
    sender = public_key.to_canonical_address()
    return sender
