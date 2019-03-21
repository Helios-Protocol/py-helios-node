from typing import (
    Tuple,
    Dict,
    Any,
    List,
)

from helios.rlp_templates.hls import P2PBlock
from hvm.rlp.consensus import NodeStakingScore
from hvm.rlp.headers import BlockHeader
from eth_typing import (
    Hash32,
    BlockNumber,
    Address)
from eth_utils import (
    ValidationError,
)

from helios.protocol.common.validators import (
    BaseValidator,
    BaseBlockHeadersValidator,
)
from helios.protocol.common.types import (
    BlockBodyBundles,
    NodeDataBundles,
    ReceiptsBundles,
)

from hvm.db.consensus import ConsensusDB

from . import constants

from hvm.types import Timestamp

class GetBlockHeadersValidator(BaseBlockHeadersValidator):
    protocol_max_request_size = constants.MAX_HEADERS_FETCH


class GetNodeDataValidator(BaseValidator[NodeDataBundles]):
    def __init__(self, node_hashes: Tuple[Hash32, ...]) -> None:
        self.node_hashes = node_hashes

    def validate_result(self, response: NodeDataBundles) -> None:
        if not response:
            # an empty response is always valid
            return

        node_keys = tuple(node_key for node_key, node in response)
        node_key_set = set(node_keys)

        if len(node_keys) != len(node_key_set):
            raise ValidationError("Response may not contain duplicate nodes")

        unexpected_keys = node_key_set.difference(self.node_hashes)

        if unexpected_keys:
            raise ValidationError(
                "Response contains {0} unexpected nodes".format(len(unexpected_keys))
            )


class ReceiptsValidator(BaseValidator[ReceiptsBundles]):
    def __init__(self, headers: Tuple[BlockHeader, ...]) -> None:
        self.headers = headers

    def validate_result(self, result: ReceiptsBundles) -> None:
        if not result:
            # empty result is always valid.
            return

        expected_receipt_roots = set(header.receipt_root for header in self.headers)
        actual_receipt_roots = set(
            root_hash
            for receipt, (root_hash, trie_data)
            in result
        )

        unexpected_roots = actual_receipt_roots.difference(expected_receipt_roots)

        if unexpected_roots:
            raise ValidationError(
                "Got {0} unexpected receipt roots".format(len(unexpected_roots))
            )


class GetBlockBodiesValidator(BaseValidator[BlockBodyBundles]):
    def __init__(self, headers: Tuple[BlockHeader, ...]) -> None:
        self.headers = headers

    def validate_result(self, response: BlockBodyBundles) -> None:
        expected_keys = {
            (header.transaction_root, header.uncles_hash)
            for header in self.headers
        }
        actual_keys = {
            (txn_root, uncles_hash)
            for body, (txn_root, trie_data), uncles_hash
            in response
        }
        unexpected_keys = actual_keys.difference(expected_keys)
        if unexpected_keys:
            raise ValidationError(
                "Got {0} unexpected block bodies".format(len(unexpected_keys))
            )


class GetBlocksValidator(BaseValidator[Tuple[P2PBlock, ...]]):
    def __init__(self, block_hashes: Tuple[Hash32, ...]) -> None:
        self.block_hashes = block_hashes

    def validate_result(self, response: Tuple[P2PBlock, ...]) -> None:
        if not response:
            # an empty response is always valid
            return

        received_block_hashes = tuple(block.header.hash for block in response)
        received_block_hashes_set = set(received_block_hashes)

        if len(received_block_hashes) != len(received_block_hashes_set):
            raise ValidationError("Response may not contain duplicate blocks")

        unexpected_hashes = received_block_hashes_set.difference(self.block_hashes)

        if unexpected_hashes:
            raise ValidationError(
                "Response contains {0} unexpected blocks".format(len(unexpected_hashes))
            )

class GetChainSegmentValidator(BaseValidator[Tuple[P2PBlock, ...]]):
    def __init__(self, chain_address: Address) -> None:
        self.chain_address = chain_address

    def validate_result(self, response: Tuple[P2PBlock, ...]) -> None:
        if not response:
            # an empty response is always valid
            return

        for block in response:
            if block.header.chain_address != self.chain_address:
                raise ValidationError(
                    "Received blocks on wrong chain"
                )

class GetChainsValidator(BaseValidator[Tuple[Tuple[P2PBlock], ...]]):
    def __init__(self, expected_chain_head_hash_fragments: List[bytes]) -> None:
        self.expected_chain_head_hash_fragments = set(expected_chain_head_hash_fragments)
        if len(expected_chain_head_hash_fragments) > 0:
            self.fragment_length = len(expected_chain_head_hash_fragments[0])
        else:
            self.fragment_length = 0

    def validate_result(self, response: Tuple[Tuple[P2PBlock], ...]) -> None:
        if not response:
            # an empty response is always valid
            return

        for chain in response:
            if len(chain) > 0:
                chain_head = chain[-1]
                if chain_head.header.hash[:self.fragment_length] not in self.expected_chain_head_hash_fragments:
                    # Sort the chain and check again just in case they came in the wrong order
                    chain = sorted(chain, key=lambda block: block.header.block_number)
                    chain_head = chain[-1]
                    if chain_head.header.hash[:self.fragment_length] not in self.expected_chain_head_hash_fragments:
                        all_block_fragments = []
                        for block in chain:
                            all_block_fragments.append(block.header.hash[:self.fragment_length])
                        raise ValidationError(
                            "Response contains the incorrect chain head blocks. All expected head hashes {}, entire received chain {}".format(self.expected_chain_head_hash_fragments, all_block_fragments)
                        )


class GetNodeStakingScoreValidator(BaseValidator[NodeStakingScore]):
    def __init__(self, since_block: BlockNumber, consensus_db:ConsensusDB) -> None:
        self.since_block = since_block
        self.consensus_db = consensus_db

    def validate_result(self, response: NodeStakingScore) -> None:
        if not response:
            # an empty response is always valid
            return


        #Since this function shouldn't be called very often, we can run this expensive validation. It will make sure
        #the node doesn't accidentally include any invalid node staking scores which will invalidate the entire
        #reward bundle and they will have to re-create it.
        self.consensus_db.validate_node_staking_score(response, self.since_block)



# def GetChronoligcalBlockHashFragmentsValidator(BaseValidator[Dict[str, Any]]):
#     def __init__(self, timestamp: Timestamp, fragment_length:int) -> None:
#         self.timestamp = timestamp
#         self.fragment_length = fragment_length
#
#     def validate_result(self, response: Dict[str, Any]) -> None:
#         if not response:
#             # an empty response is always valid
#             return
#
#         if response['timestamp'] != self.timestamp:
#             raise ValidationError(
#                 "Response is for unexpected timestamp"
#             )
#
#         if response['fragment_length'] != self.fragment_length:
#             raise ValidationError(
#                 "Response contains unexpected fragment length"
#             )
#

def get_hash_fragments_payload_validator(request: Dict[str, Any], response: Dict[str, Any]) -> None:
    if not response:
        # an empty response is always valid
        return

    if response['timestamp'] != request['timestamp']:
        raise ValidationError(
            "Response is for unexpected timestamp"
        )

    if response['fragment_length'] != request['fragment_length']:
        raise ValidationError(
            "Response contains unexpected fragment length"
        )


