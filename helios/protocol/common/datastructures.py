from hvm.constants import TIME_BETWEEN_HEAD_HASH_SAVE
from hvm.types import Timestamp
from typing import (
    List,
    Union,
    TYPE_CHECKING,
    Optional,
)
from eth_typing import Hash32

from helios.protocol.hls.sync import get_sync_stage_for_historical_root_hash_timestamp
if TYPE_CHECKING:
    from helios.protocol.common.peer import HLSPeer

class HashFragmentRequestHistory:
    def __init__(self,
                 timestamp: Timestamp,
                 fragment_length: int,
                 hexary_trie_root_hash_of_complete_window: Hash32,
                 local_hashes_sent_to_peer: List[Union[Timestamp, Hash32]],
                 ):
        self.timestamp: Timestamp = timestamp
        self.fragment_length: int = fragment_length
        self.hexary_trie_root_hash_of_complete_window: Hash32 = hexary_trie_root_hash_of_complete_window
        self.local_hashes_sent_to_peer: List[Union[Timestamp, Hash32]] = local_hashes_sent_to_peer


class HashFragmentBundle:
    def __init__(self,
                 fragments: List[bytes],
                 root_hash_of_the_full_hashes: Hash32,
                 ):
        self.fragments: List[bytes] = fragments
        self.root_hash_of_the_full_hashes: Hash32 = root_hash_of_the_full_hashes


class SyncParameters():
    def __init__(self,
                 timestamp_for_root_hash: Timestamp,
                 local_root_hash: Hash32,
                 consensus_root_hash: Hash32,
                 peers_to_sync_with: List['HLSPeer'],
                 sync_stage_override: Optional[int] = None,
                ):

        #this is the timestamp of the currently syncing root hash
        self.timestamp_for_root_hash: Timestamp = timestamp_for_root_hash

        if sync_stage_override is None:
            self.sync_stage = get_sync_stage_for_historical_root_hash_timestamp(self.timestamp_for_root_hash)
        else:
            self.sync_stage = sync_stage_override

        #this is the timestamp for the currently syncing chronolical block window.
        self.timestamp_for_chronoligcal_block_window: Timestamp = timestamp_for_root_hash - TIME_BETWEEN_HEAD_HASH_SAVE

        self.local_root_hash: Hash32 = local_root_hash
        self.consensus_root_hash: Hash32 = consensus_root_hash
        self.peers_to_sync_with: List['HLSPeer'] = peers_to_sync_with


class ChainRequestInfo():
    def __init__(self, peer: 'HLSPeer', head_root_timestamp: Timestamp, head_root_hash: Hash32, start_idx: int, end_idx: int):
        self.peer = peer
        self.head_root_timestamp = head_root_timestamp
        self.head_root_hash = head_root_hash
        self.start_idx = start_idx
        self.end_idx = end_idx


class FastSyncParameters():
    def __init__(self,
                 expected_block_hash_fragments: List[bytes],
                 chain_idx_that_we_need: List[int],
                ):

        self.expected_block_hash_fragments: List[bytes] = expected_block_hash_fragments
        self.chain_idx_that_we_need: List[int] = chain_idx_that_we_need
