from concurrent.futures import ProcessPoolExecutor
import logging
import os
import rlp
from eth_keys import keys

from hvm.utils.numeric import big_endian_to_int

from eth_keys.exceptions import (
    BadSignature,
)

from hvm.exceptions import (
    ValidationError,
)

def sxor(s1: bytes, s2: bytes) -> bytes:
    if len(s1) != len(s2):
        raise ValueError("Cannot sxor strings of different length")
    return bytes(x ^ y for x, y in zip(s1, s2))


def roundup_16(x):
    """Rounds up the given value to the next multiple of 16."""
    remainder = x % 16
    if remainder != 0:
        x += 16 - remainder
    return x


def gen_request_id() -> int:
    return big_endian_to_int(os.urandom(8))


def get_devp2p_cmd_id(msg: bytes) -> int:
    """Return the cmd_id for the given devp2p msg.

    The cmd_id, also known as the payload type, is always the first entry of the RLP, interpreted
    as an integer.
    """
    return rlp.decode(msg[:1], sedes=rlp.sedes.big_endian_int)


def get_process_pool_executor():
    # Use CPU_COUNT - 1 processes to make sure we always leave one CPU idle so that it can run
    # asyncio's event loop.
    os_cpu_count = os.cpu_count()
    if os_cpu_count in (None, 0):
        # Need this because os.cpu_count() returns None when the # of CPUs is indeterminable.
        logger = logging.getLogger('hp2p.utils')
        logger.warning(
            f"Could not determine number of CPUs, defaulting to 1 instead of {os_cpu_count}"
        )
        cpu_count = 1
    else:
        cpu_count = os_cpu_count - 1
    return ProcessPoolExecutor(cpu_count)

def extract_wallet_verification_sender(salt, v, r, s) -> bytes:
   
    vrs = (v, r, s)
    signature = keys.Signature(vrs=vrs)
    
    parts_for_sig = salt
    message = rlp.encode(parts_for_sig)
    
    public_key = signature.recover_public_key_from_msg(message)
    sender = public_key.to_canonical_address()
    return sender

def create_wallet_verification_signature(salt, private_key):
    parts_for_sig = salt
    message = rlp.encode(parts_for_sig)
    signature = private_key.sign_msg(message)
    v, r, s = signature.vrs
    return v, r, s



def validate_transaction_signature(salt, v, r, s) -> None:
    vrs = (v, r, s)
    signature = keys.Signature(vrs=vrs)
    
    parts_for_sig = salt
    message = rlp.encode(parts_for_sig)
    
    try:
        public_key = signature.recover_public_key_from_msg(message)
    except BadSignature as e:
        raise ValidationError("Bad Signature: {0}".format(str(e)))

    if not signature.verify_msg(message, public_key):
        raise ValidationError("Invalid Signature")