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
    from helios.protocol.common.peer import BasePeer

class AdditiveSyncRequestHistory:
    def __init__(self,
                 chronological_window_timestamp: Timestamp,
                 fragment_length: int,
                 root_hash_of_just_this_chronological_block_window: Hash32,
                 local_hashes_sent_to_peer: List[Union[Timestamp, Hash32]],

                ):
        self.chronological_window_timestamp: Timestamp = chronological_window_timestamp
        self.fragment_length: int = fragment_length
        self.root_hash_of_just_this_chronological_block_window: Hash32 = root_hash_of_just_this_chronological_block_window
        self.local_hashes_sent_to_peer: List[Union[Timestamp, Hash32]] = local_hashes_sent_to_peer


class ChronologicalBlockHashFragmentBundle:
    def __init__(self,
                 fragments: List[bytes],
                 root_hash_of_just_this_chronological_block_window: Hash32,
                 ):
        self.fragments: List[bytes] = fragments
        self.root_hash_of_just_this_chronological_block_window: Hash32 = root_hash_of_just_this_chronological_block_window


class SyncParameters():
    def __init__(self,
                 timestamp_for_root_hash: Timestamp,
                 local_root_hash: Hash32,
                 consensus_root_hash: Hash32,
                 peers_to_sync_with: List['BasePeer'],
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
        self.peers_to_sync_with: List[HLSPeer] = peers_to_sync_with


