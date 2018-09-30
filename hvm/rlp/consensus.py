from abc import (
    ABCMeta,
    abstractmethod
)

import itertools

import rlp
from rlp.sedes import (
    big_endian_int,
    f_big_endian_int,
    CountableList,
    binary,
)

from hvm.rlp.sedes import (
    hash32,   
    address,     
)

from eth_typing import (
    Hash32,
    Address,
)

from eth_bloom import BloomFilter

from hvm.exceptions import ValidationError

from .sedes import (
    int256,
    int32,
)

from hvm.utils.transactions import (
    extract_chain_id,
)

from hvm.utils.node_score import (
    create_node_staking_score_signature,
    validate_node_staking_score_signature,
    extract_node_staking_score_sender,
)

from hvm.rlp.blocks import BaseBlock

from .logs import Log

from hvm.validation import (
    validate_lt_secpk1n2,
    validate_uint256,
    validate_lt_secpk1n,
    validate_lte,
    validate_gte,
    validate_canonical_address,
)

from eth_hash.auto import keccak

from typing import Iterable, Any



class BaseBlockConflictMessage(rlp.Serializable, metaclass=ABCMeta):
    pass



class PeerNodeHealth(rlp.Serializable, metaclass=ABCMeta):
    fields = [
        ('requests_sent', f_big_endian_int),
        ('failed_requests', f_big_endian_int),
        ('average_response_time', f_big_endian_int) #milliseconds
    ]

    def __init__(self,
                 requests_sent: int=0,
                 failed_requests: int = 0,
                 average_response_time: int = 0,
                 **kwargs: Any) -> None:
        super(PeerNodeHealth, self).__init__(requests_sent, failed_requests, average_response_time, **kwargs)


class NodeStakingScore(rlp.Serializable, metaclass=ABCMeta):
    fields = [
        ('recipient_node_wallet_address', address),
        ('score', f_big_endian_int),
        ('since_block_number', f_big_endian_int),
        ('timestamp', f_big_endian_int),
        ('v', big_endian_int),
        ('r', big_endian_int),
        ('s', big_endian_int),
    ]


    _cache = True
    _sender = None
    _valid_score = None
    
    
    @property
    def hash(self) -> bytes:
        return keccak(rlp.encode(self))

    @property
    def sender(self) -> Address:
        """
        Convenience property for the return value of `get_sender`
        """
        return self.get_sender()

    @property
    def chain_id(self):
        return extract_chain_id(self.v)

    @property
    def v_min(self):
        return 35 + (2 * self.chain_id)

    @property
    def v_max(self):
        return 36 + (2 * self.chain_id)
        
    


    def validate(self):

        validate_canonical_address(self.to, title="Transaction.to")
        validate_uint256(self.score, title="Transaction.value")

        validate_uint256(self.v, title="Transaction.v")
        validate_uint256(self.r, title="Transaction.r")
        validate_uint256(self.s, title="Transaction.s")

        validate_lt_secpk1n(self.r, title="Transaction.r")
        validate_gte(self.r, minimum=1, title="Transaction.r")
        validate_lt_secpk1n(self.s, title="Transaction.s")
        validate_gte(self.s, minimum=1, title="Transaction.s")

        validate_gte(self.v, minimum=self.v_min, title="Transaction.v")
        validate_lte(self.v, maximum=self.v_max, title="Transaction.v")

        validate_lt_secpk1n2(self.s, title="Transaction.s")
        
    @property
    def is_signature_valid(self) -> bool:
        try:
            self.check_signature_validity()
        except ValidationError:
            return False
        else:
            return True
        
    def check_signature_validity(self):
        if self._cache:
            if self._valid_score is not None:
                return self._valid_score
            else:
                self._valid_score = False
                self._sender = validate_node_staking_score_signature(self, return_sender=True)
                # if it gets this far without an exception, then the signature is valid
                self._valid_score = True
        else:
            validate_node_staking_score_signature(self)

    def get_sender(self):
        if self._cache:
            if self._sender is not None:
                return self._sender
            else:
                # here if the signature is invalid it will throw an error and not return anything.
                self.check_signature_validity()
                # if it makes it this far, then it has saved the sender
                return self._sender
        else:
            return extract_node_staking_score_sender(self)

    

    def get_signed(self, private_key, chain_id):
        v, r, s = create_node_staking_score_signature(self, private_key, chain_id)
        return self.copy(
            v=v,
            r=r,
            s=s,
        )
    

    def __eq__(self, other):
        return self.hash == other.hash

    def __hash__(self):
        return hash(self.hash)