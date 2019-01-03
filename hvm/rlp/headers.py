from abc import (
    ABCMeta,
    abstractmethod
)
import time
from typing import (
    Any,
    Iterator,
    Optional,
    Tuple,
    Union,
    overload,
)

import rlp_cython as rlp
from rlp_cython.sedes import (
    big_endian_int,
    Binary,
    binary,
    f_big_endian_int)


from cytoolz import (
    accumulate,
    sliding_window,
)
from eth_typing import (
    Address,
    Hash32,
)
from eth_utils import (
    to_dict,
    int_to_big_endian,
)

from eth_hash.auto import keccak

from hvm.constants import (
    ZERO_ADDRESS,
    ZERO_HASH32,
    EMPTY_UNCLE_HASH,
    GENESIS_NONCE,
    BLANK_ROOT_HASH,
    BLOCK_GAS_LIMIT)
from hvm.exceptions import (
    ValidationError,
)
from hvm.utils.rlp import convert_rlp_to_correct_class

from hvm.validation import (
    validate_uint256,
    validate_is_integer,
    validate_is_bytes,
    validate_lt_secpk1n,
    validate_lte,
    validate_gte,
    validate_canonical_address,
)

from hvm.utils.hexadecimal import (
    encode_hex,
)
from hvm.utils.numeric import (
    int_to_bytes32,
)
from hvm.utils.padding import (
    pad32,
)

from .sedes import (
    address,
    hash32,
    int32,
    int256,
    trie_root,
)

from hvm.vm.execution_context import (
    ExecutionContext,
)


HeaderParams = Union[Optional[int], bytes, Address, Hash32]

default_gas_limit = BLOCK_GAS_LIMIT

# The microblockheader is used to decode headers that come from rlp_cython.
class MicroBlockHeader(rlp.Serializable, metaclass=ABCMeta):

    fields = [
        ('chain_address', address),
        ('parent_hash', hash32),
        ('transaction_root', trie_root),
        ('receive_transaction_root', trie_root),
        ('block_number', big_endian_int),
        ('timestamp', big_endian_int),
        ('extra_data', binary),
        ('reward_hash', hash32),
        ('v', big_endian_int),
        ('r', big_endian_int),
        ('s', big_endian_int),
    ]

class BaseBlockHeader(rlp.Serializable, metaclass=ABCMeta):
    fields = [
        ('chain_address', address),
        ('parent_hash', hash32),
        ('transaction_root', trie_root),
        ('receive_transaction_root', trie_root),
        ('receipt_root', trie_root),
        ('bloom', int256),
        ('block_number', big_endian_int),
        ('gas_limit', big_endian_int),
        ('gas_used', big_endian_int),
        ('timestamp', big_endian_int),
        ('extra_data', binary),
        ('reward_hash', hash32),
        ('account_hash', hash32),
        ('account_balance', big_endian_int), #balance of account after transactions have occurred
        ('v', big_endian_int),
        ('r', big_endian_int),
        ('s', big_endian_int),
    ]
    #header_parts[:4] + [header_parts[6]] + header_parts[9:12]


    @overload
    def __init__(self, **kwargs: HeaderParams) -> None:
        ...

    @overload  # noqa: F811
    def __init__(self,
                 block_number: int,
                 gas_limit: int=default_gas_limit,
                 account_hash: Hash32=ZERO_HASH32,
                 account_balance: int = 0,
                 timestamp: int=None,
                 parent_hash: Hash32=ZERO_HASH32,
                 transaction_root: Hash32=BLANK_ROOT_HASH,
                 receive_transaction_root: Hash32=BLANK_ROOT_HASH,
                 receipt_root: Hash32=BLANK_ROOT_HASH,
                 bloom: int=0,
                 gas_used: int=0,
                 extra_data: bytes=b'',
                 reward_hash: bytes = ZERO_HASH32,
                 chain_address: Address = ZERO_ADDRESS,
                 v: int=0,
                 r: int=0,
                 s: int=0) -> None:
        ...

    def __init__(self,  # noqa: F811
                 block_number,
                 gas_limit = default_gas_limit,
                 account_hash = ZERO_HASH32,
                 account_balance = 0,
                 timestamp=None,
                 parent_hash=ZERO_HASH32,
                 transaction_root=BLANK_ROOT_HASH,
                 receive_transaction_root=BLANK_ROOT_HASH,
                 receipt_root=BLANK_ROOT_HASH,
                 bloom=0,
                 gas_used=0,
                 extra_data=b'',
                 reward_hash = ZERO_HASH32,
                 chain_address = ZERO_ADDRESS,
                 v=0,
                 r=0,
                 s=0):
        if timestamp is None:
            timestamp = int(time.time())


        super(BaseBlockHeader, self).__init__(
            parent_hash=parent_hash,
            transaction_root=transaction_root,
            receive_transaction_root=receive_transaction_root,
            receipt_root=receipt_root,
            bloom=bloom,
            block_number=block_number,
            gas_limit=gas_limit,
            gas_used=gas_used,
            timestamp=timestamp,
            extra_data=extra_data,
            reward_hash=reward_hash,
            account_hash=account_hash,
            account_balance = account_balance,
            chain_address = chain_address,
            v=v,
            r=r,
            s=s,
        )

    def __repr__(self) -> str:
        return '<BaseBlockHeader #{0} {1}>'.format(
            self.block_number,
            encode_hex(self.hash)[2:10],
        )

    _hash = None
    _micro_header_hash = None

    @property
    def hash(self) -> Hash32:
        if self._hash is None:
            self._hash = keccak(rlp.encode(self, sedes = self.__class__))
        return self._hash

    @property
    def micro_header_hash(self) -> Hash32:
        if self._micro_header_hash is None:
            header_parts = rlp.decode(rlp.encode(self), use_list=True)
            header_parts_for_hash = (
                    header_parts[:4] + [header_parts[6]] + header_parts[9:12] + header_parts[-3:]
            )
            self._micro_header_hash = keccak(rlp.encode(header_parts_for_hash))
        return self._micro_header_hash

    @property
    def hex_hash(self):
        return encode_hex(self.hash)

    @classmethod
    def from_parent(cls,
                    parent: 'BaseBlockHeader',
                    gas_limit: int=default_gas_limit,
                    timestamp: int=None,
                    extra_data: bytes=None,
                    transaction_root: bytes=None,
                    receive_transaction_root: bytes=None,
                    receipt_root: bytes=None,
                    account_hash: bytes=ZERO_HASH32,
                    reward_hash: bytes = None) -> 'BaseBlockHeader':
        """
        Initialize a new block header with the `parent` header as the block's
        parent hash.
        """
        if timestamp is None:
            timestamp = int(time.time())
        header_kwargs = {
            'parent_hash': parent.hash,
            'gas_limit': gas_limit,
            'block_number': parent.block_number + 1,
            'timestamp': timestamp,
            'chain_address': parent.chain_address
        }
        if account_hash is not None:
            header_kwargs['account_hash'] = account_hash
        if extra_data is not None:
            header_kwargs['extra_data'] = extra_data
        if reward_hash is not None:
            header_kwargs['reward_hash'] = reward_hash
        if transaction_root is not None:
            header_kwargs['transaction_root'] = transaction_root
        if receive_transaction_root is not None:
            header_kwargs['receive_transaction_root'] = receive_transaction_root
        if receipt_root is not None:
            header_kwargs['receipt_root'] = receipt_root

        header = cls(**header_kwargs)
        return header

    def create_execution_context(
            self, prev_hashes: Union[Tuple[bytes], Tuple[bytes, bytes]]) -> ExecutionContext:

        return ExecutionContext(
            timestamp=self.timestamp,
            block_number=self.block_number,
            gas_limit=self.gas_limit,
            prev_hashes=prev_hashes,
        )
        
    #
    # Signature and Sender
    #

    def get_message_for_signing(self, chain_id: int = None) -> bytes:
        if chain_id is None:
            chain_id = self.chain_id

        header_parts = rlp.decode(rlp.encode(self, sedes=self.__class__), use_list=True)
        header_parts_for_signature = (
                header_parts[:4] + [header_parts[6]] + header_parts[9:12] + [
            int_to_big_endian(chain_id), b'', b'']
        )
        # header_parts_for_signature = (
        #         header_parts[:3] + [header_parts[5]] + header_parts[8:11] + [header_parts[12]] + [header_parts[13]] + [
        #     int_to_big_endian(chain_id), b'', b'']
        # )
        message = rlp.encode(header_parts_for_signature)
        return message

    @property
    def is_signature_valid(self) -> bool:
        try:
            self.check_signature_validity()
        except ValidationError:
            return False
        else:
            return True
      

    @property
    def sender(self) -> Address:
        """
        Convenience property for the return value of `get_sender`
        """
        return self.get_sender()
    
    @abstractmethod
    def check_signature_validity(self) -> None:
        """
        Checks signature validity, raising a ValidationError if the signature
        is invalid.
        """
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def get_sender(self) -> Address:
        """
        Get the 20-byte address which sent this transaction.
        """
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def get_signed(self, private_key, chain_id) -> 'BaseBlockHeader':
        raise NotImplementedError("Must be implemented by subclasses")


    #
    # MicroHeader API
    #
    @classmethod
    def from_micro_header(cls, micro_header:MicroBlockHeader):
        return convert_rlp_to_correct_class(cls, micro_header)
        


from hvm.utils.blocks import (
    create_block_header_signature,
    extract_block_header_sender,
    validate_block_header_signature,
    is_eip_155_signed_block_header,
    extract_chain_id,
)


class BlockHeader(BaseBlockHeader):
    def check_signature_validity(self):
        validate_block_header_signature(self)

    def get_sender(self):
        return extract_block_header_sender(self)
    
        
    def get_signed(self, private_key, chain_id):
        v,r,s = create_block_header_signature(self, private_key, chain_id)
        return self.copy(
                v=v,
                r=r,
                s=s,
                )

    @property
    def chain_id(self):
        if is_eip_155_signed_block_header(self):
            return extract_chain_id(self.v)


    @property
    def v_min(self):
        if is_eip_155_signed_block_header(self):
            return 35 + (2 * self.chain_id)


    @property
    def v_max(self):
        if is_eip_155_signed_block_header(self):
            return 36 + (2 * self.chain_id)



        
class CollationHeader(rlp.Serializable):
    """The header of a collation signed by the proposer."""

    fields_with_sizes = [
        ("shard_id", int32, 32),
        ("chunk_root", hash32, 32),
        ("period", int32, 32),
        ("proposer_address", address, 32),
    ]
    fields = [(name, sedes) for name, sedes, _ in fields_with_sizes]
    smc_encoded_size = sum(size for _, _, size in fields_with_sizes)

    def __repr__(self) -> str:
        return "<CollationHeader shard={} period={} hash={}>".format(
            self.shard_id,
            self.period,
            encode_hex(self.hash)[2:10],
        )

    @property
    def hash(self) -> Hash32:
        return keccak(self.encode_for_smc())

    def encode_for_smc(self) -> bytes:
        encoded = b"".join([
            int_to_bytes32(self.shard_id),
            self.chunk_root,
            int_to_bytes32(self.period),
            pad32(self.proposer_address),
        ])
        if len(encoded) != self.smc_encoded_size:
            raise ValueError("Encoded header size is {} instead of {} bytes".format(
                len(encoded),
                self.smc_encoded_size,
            ))
        return encoded

    @classmethod
    @to_dict
    def _decode_header_to_dict(cls, encoded_header: bytes) -> Iterator[Tuple[str, Any]]:
        if len(encoded_header) != cls.smc_encoded_size:
            raise ValidationError(
                "Expected encoded header to be of size: {0}. Got size {1} instead.\n- {2}".format(
                    cls.smc_encoded_size,
                    len(encoded_header),
                    encode_hex(encoded_header),
                )
            )

        start_indices = accumulate(lambda i, field: i + field[2], cls.fields_with_sizes, 0)
        field_bounds = sliding_window(2, start_indices)
        for byte_range, field in zip(field_bounds, cls._meta.fields):
            start_index, end_index = byte_range
            field_name, field_type = field

            field_bytes = encoded_header[start_index:end_index]
            if field_type == rlp.sedes.big_endian_int:
                # remove the leading zeros, to avoid `not minimal length` error in deserialization
                formatted_field_bytes = field_bytes.lstrip(b'\x00')
            elif field_type == address:
                formatted_field_bytes = field_bytes[-20:]
            else:
                formatted_field_bytes = field_bytes
            yield field_name, field_type.deserialize(formatted_field_bytes)

    @classmethod
    def decode_from_smc(cls, encoded_header: bytes) -> "CollationHeader":
        header_kwargs = cls._decode_header_to_dict(encoded_header)
        header = cls(**header_kwargs)
        return header

#test = BaseUnsignedBlockHeader()