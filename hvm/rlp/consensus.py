from abc import (
    ABCMeta,
    abstractmethod
)

import itertools

import rlp_cython as rlp
from rlp_cython.sedes import (
    big_endian_int,
    f_big_endian_int,
    CountableList,
    binary,
)

from hvm.db.trie import make_trie_root_and_nodes

from eth_utils import int_to_big_endian

from hvm.rlp.sedes import (
    hash32,   
    address,     
)

from eth_typing import (
    Hash32,
    Address,
)

from hvm.exceptions import ValidationError


from hvm.utils.transactions import (
    extract_chain_id,
)

from hvm.utils.node_score import (
    create_node_staking_score_signature,
    validate_node_staking_score_signature,
    extract_node_staking_score_sender,
)


from hvm.validation import (
    validate_lt_secpk1n2,
    validate_uint256,
    validate_lt_secpk1n,
    validate_lte,
    validate_gte,
    validate_canonical_address,
)

from eth_hash.auto import keccak

from typing import Iterable, Any, List



class BaseBlockConflictMessage(rlp.Serializable, metaclass=ABCMeta):
    pass



class PeerNodeHealth(rlp.Serializable, metaclass=ABCMeta):
    fields = [
        ('requests_sent', f_big_endian_int),
        ('failed_requests', f_big_endian_int),
        ('average_response_time', f_big_endian_int) #microseconds
    ]

    def __init__(self,
                 requests_sent: int=0,
                 failed_requests: int = 0,
                 average_response_time: int = 0,
                 **kwargs: Any) -> None:
        super(PeerNodeHealth, self).__init__(requests_sent, failed_requests, average_response_time, **kwargs)

    def __str__(self):
        output = "requests_sent = {} \n".format(self.requests_sent)
        output += "failed_requests = {} \n".format(self.failed_requests)
        output += "average_response_time = {} \n".format(self.average_response_time)
        return output


class NodeStakingScore(rlp.Serializable, metaclass=ABCMeta):
    fields = [
        ('recipient_node_wallet_address', address),
        ('score', f_big_endian_int), #a score out of 1,000,000
        ('since_block_number', f_big_endian_int),
        ('timestamp', f_big_endian_int),
        ('head_hash_of_sender_chain', hash32),
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

        validate_canonical_address(self.recipient_node_wallet_address, title="recipient_node_wallet_address")
        validate_uint256(self.score, title="score")
        validate_uint256(self.since_block_number, title="since_block_number")
        validate_uint256(self.timestamp, title="timestamp")

        validate_uint256(self.v, title="v")
        validate_uint256(self.r, title="r")
        validate_uint256(self.s, title="s")

        validate_lt_secpk1n(self.r, title="r")
        validate_gte(self.r, minimum=1, title="r")
        validate_lt_secpk1n(self.s, title="s")
        validate_gte(self.s, minimum=1, title="s")

        validate_gte(self.v, minimum=self.v_min, title="v")
        validate_lte(self.v, maximum=self.v_max, title="v")

        validate_lt_secpk1n2(self.s, title="s")

    @property
    def is_signature_valid(self) -> bool:
        try:
            self.check_signature_validity()
        except ValidationError:
            return False
        else:
            return True

    def get_message_for_signing(self, chain_id: int = None) -> bytes:
        if chain_id is None:
            chain_id = self.chain_id

        transaction_parts = rlp.decode(rlp.encode(self), use_list=True)

        transaction_parts_for_signature = transaction_parts[:-3] + [int_to_big_endian(chain_id), b'', b'']

        message = rlp.encode(transaction_parts_for_signature)
        return message


    def check_signature_validity(self):
        if self._cache:
            if self._valid_score is not None:
                if not self._valid_score:
                    raise ValidationError()
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


class StakeRewardType1(rlp.Serializable, metaclass=ABCMeta):
    fields = [
        ('amount', big_endian_int),
    ]

    def __init__(self,
                 amount: int = 0,
                 **kwargs: Any) -> None:

        super(StakeRewardType1, self).__init__(amount, **kwargs)

class StakeRewardType2(rlp.Serializable, metaclass=ABCMeta):
    proof_class = NodeStakingScore
    fields = [
        ('amount', big_endian_int),
        ('proof', CountableList(NodeStakingScore)),
    ]

    def __init__(self,
                 amount: int = 0,
                 proof: List[NodeStakingScore] = [],
                 **kwargs: Any) -> None:

        super(StakeRewardType2, self).__init__(amount, proof, **kwargs)

    # @property
    # def hash(self) -> bytes:
    #     return keccak(self.get_message_for_hash())
    #
    # def get_message_for_hash(self):
    #     return rlp.encode([self.amount, self.proof_root_hash])

    @property
    def proof_root_hash(self) -> bytes:
        root_hash, kv_nodes = make_trie_root_and_nodes(self.proof)
        return root_hash

class BaseRewardBundle(rlp.Serializable, metaclass=ABCMeta):
    reward_type_1_class = StakeRewardType1
    reward_type_2_class = StakeRewardType2

    fields = [
        ('reward_type_1', StakeRewardType1),
        ('reward_type_2', StakeRewardType2),
    ]

    def __init__(self,
                 reward_type_1: StakeRewardType1 = None,
                 reward_type_2: StakeRewardType2 = None,
                 **kwargs: Any) -> None:

        if reward_type_1 is None:
            reward_type_1 = StakeRewardType1()

        if reward_type_2 is None:
            reward_type_2 = StakeRewardType2()

        super(BaseRewardBundle, self).__init__(reward_type_1, reward_type_2, **kwargs)

    @property
    def hash(self) -> Hash32:
        return keccak(self.get_message_for_hash())

    def get_message_for_hash(self):
        return rlp.encode([self.reward_type_1, self.reward_type_2.amount, self.reward_type_2.proof_root_hash])


class StakeRewardBundle(BaseRewardBundle):
    pass


#
# Sedes
#


class StakeRewardBundleOrBinary:

    def serialize(self, obj):
        if obj == b'':
            return b''
        return StakeRewardBundle.serialize(obj)

    def deserialize(self, serial, to_list = False):
        if serial == b'':
            return b''
        return StakeRewardBundle.deserialize(serial)

stake_reward_bundle_or_binary = StakeRewardBundleOrBinary()

class StakeRewardBundleOrNone:

    def serialize(self, obj):
        if obj == None:
            return b''
        return StakeRewardBundle.serialize(obj)

    def deserialize(self, serial, to_list = False):
        if serial == b'':
            return None
        return StakeRewardBundle.deserialize(serial)

stake_reward_bundle_or_none = StakeRewardBundleOrNone()