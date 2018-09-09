import rlp

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

from hvm.rlp.headers import (
    BaseBlockHeader,
)


EIP155_CHAIN_ID_OFFSET = 35
V_OFFSET = 27


def is_eip_155_signed_block_header(block_header: BaseBlockHeader) -> bool:
    if block_header.v >= EIP155_CHAIN_ID_OFFSET:
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


def create_block_header_signature(block_header: BaseBlockHeader, private_key, chain_id):
    transaction_parts = rlp.decode(rlp.encode(block_header), use_list = True)
    transaction_parts_for_signature = (
        transaction_parts[:-3] + [int_to_big_endian(chain_id), b'', b'']
    )
    message = rlp.encode(transaction_parts_for_signature)
    
    signature = private_key.sign_msg(message)

    canonical_v, r, s = signature.vrs

    v = canonical_v + chain_id * 2 + EIP155_CHAIN_ID_OFFSET

    return v, r, s


def validate_block_header_signature(block_header: BaseBlockHeader) -> None:
    if is_eip_155_signed_block_header(block_header):
        v = extract_signature_v(block_header.v)
    else:
        v = block_header.v

    canonical_v = v - 27
    vrs = (canonical_v, block_header.r, block_header.s)
    signature = keys.Signature(vrs=vrs)
     
    transaction_parts = rlp.decode(rlp.encode(block_header), use_list = True)
    transaction_parts_for_signature = (
        transaction_parts[:-3] + [int_to_big_endian(block_header.chain_id), b'', b'']
    )
    message = rlp.encode(transaction_parts_for_signature)
    
    try:
        public_key = signature.recover_public_key_from_msg(message)
    except BadSignature as e:
        raise ValidationError("Bad Signature: {0}".format(str(e)))

    if not signature.verify_msg(message, public_key):
        raise ValidationError("Invalid Signature")


def extract_block_header_sender(block_header: BaseBlockHeader) -> bytes:
    if is_eip_155_signed_block_header(block_header):
        if is_even(block_header.v):
            v = 28
        else:
            v = 27
    else:
        v = block_header.v

    r, s = block_header.r, block_header.s

    canonical_v = v - 27
    vrs = (canonical_v, r, s)
    signature = keys.Signature(vrs=vrs)
    
    transaction_parts = rlp.decode(rlp.encode(block_header), use_list = True)
    transaction_parts_for_signature = (
        transaction_parts[:-3] + [int_to_big_endian(block_header.chain_id), b'', b'']
    )
    message = rlp.encode(transaction_parts_for_signature)
    
    public_key = signature.recover_public_key_from_msg(message)
    sender = public_key.to_canonical_address()
    return sender

def get_block_average_transaction_gas_price(block):
    total_sum = 0
    num_tx = 0
    for transaction in block.transactions:
        num_tx += 1
        total_sum += transaction.gas_price
        
    average = total_sum/num_tx
    return average
        






