from eth_utils import to_wei

SUPPORTED_RLPX_VERSION = 4

# Overhead added by ECIES encryption
ENCRYPT_OVERHEAD_LENGTH = 113

# Lentgh of elliptic S256 signatures
SIGNATURE_LEN = 65

# Length of public keys: 512 bit keys in uncompressed form, without format byte
PUBKEY_LEN = 64

# Hash length (for nonce etc)
HASH_LEN = 32

# Length of initial auth handshake message
AUTH_MSG_LEN = SIGNATURE_LEN + HASH_LEN + PUBKEY_LEN + HASH_LEN + 1

# Length of auth ack handshake message
AUTH_ACK_LEN = PUBKEY_LEN + HASH_LEN + 1

# Length of encrypted pre-EIP-8 initiator handshake
ENCRYPTED_AUTH_MSG_LEN = AUTH_MSG_LEN + ENCRYPT_OVERHEAD_LENGTH

# Length of encrypted pre-EIP-8 handshake reply
ENCRYPTED_AUTH_ACK_LEN = AUTH_ACK_LEN + ENCRYPT_OVERHEAD_LENGTH

# Length of an RLPx packet's header
HEADER_LEN = 16

# Length of an RLPx header's/frame's MAC
MAC_LEN = 16

# The amount of seconds a connection can be idle.
CONN_IDLE_TIMEOUT = 30

# Timeout used when waiting for a reply from a remote node.
REPLY_TIMEOUT = 3
MAX_REQUEST_ATTEMPTS = 3

# Default timeout before giving up on a caller-initiated interaction
COMPLETION_TIMEOUT = 5

MAINNET_BOOTNODES = (
                     'enode://16a5d307b0152d3e3e49e8b1f2f08c403a7b8b2f27667ae0ef10486019326b71c50fac7b2cfc6c278ca6abc54bf8e81e376a6a82996ffaea599aea85c6f5f831@142.58.49.25:30303',
                    'enode://a8dc7d11801fceb6018df377bc37bad5d4f580d1c36c57b1055595daaed54f7ec15ba1c247b317db1b5d37e439de07e42dbc5ae037dd90f6e77e4c69453c5f0d@142.58.122.209:30303',
                    'enode://1e95a05d9601763786055cd48e21c883be82981acb1db56e8e5f8e9bae68697e322266b749d3014bf1d21884d90907c6846dab9e0fbe73a56bbeb04e49a486e0@50.68.92.147:30303',
                    'enode://23ac1a7e9389d549b05d8c5596478276bc2d840a25a6e890fbb1d25e7c953e1156ddac284983ec85c057ac9f5d13c0992a16ffd9a2d938bc23e4d75ef3d48a69@199.193.6.184:30303'
)
ROPSTEN_BOOTNODES = ()
DISCOVERY_V5_BOOTNODES = ()

# Maximum peers number, we'll try to keep open connections up to this number of peers
DEFAULT_MAX_PEERS = 25
DEFAULT_MAX_PEERS_BOOTNODE = 35

# Maximum allowed depth for chain reorgs.
MAX_REORG_DEPTH = 24

# Random sampling rate (i.e. every K-th) for header seal checks during light/fast sync. Apparently
# 100 was the optimal value determined by geth devs
# (https://github.com/ethereum/go-ethereum/pull/1889#issue-47241762), but in order to err on the
# side of caution, we use a higher value.
SEAL_CHECK_RANDOM_SAMPLE_RATE = 48


# The amount of time that the BasePeerPool will wait for a peer to boot before
# aborting the connection attempt.
DEFAULT_PEER_BOOT_TIMEOUT = 20

# The maximum number of concurrent attempts to establis new peer connections
MAX_CONCURRENT_CONNECTION_ATTEMPTS = 10

# The amount of seconds a connection can be idle.
HANDSHAKE_TIMEOUT = 10

############
# NEW HELIOS
############
#the minimum number of peers to be connected to before consensus is ready.
MIN_SAFE_PEERS = 1
# the minimum amount of stake that connected peers have before we consider consensus ready
MIN_SAFE_PEER_STAKE_FOR_CONSENSUS_READY = to_wei(300000, 'ether')
#the minimum amount of time to wait between loading historical root hash from database
LOCAL_ROOT_HASH_CHECK_MIN_TIME_PERIOD = 2
#if this amount of time passes, and none of the peers have a different block than ours, we delete the conflicblock
BLOCK_CONFLICT_RESOLUTION_PERIOD = 60
#the amount of time to wait between removing data from disconnected peers
CONSENUS_PEER_DISCONNECT_CHECK_PERIOD = 120
CONSENSUS_CHECK_READY_TIME_PERIOD = 2
FAST_SYNC_NUM_CHAINS_TO_REQUEST = 5
ASK_BOOT_NODE_FOR_STAKE_CUTOFF_PERIOD = 60*24

CONSENSUS_SYNC_TIME_PERIOD = 3 #the amount of time between checking that we are in sync with peers
CONSENSUS_CHECK_MIN_GAS_SYSTEM_READY_TIME_PERIOD = 5
CONSENSUS_CHECK_CURRENT_SYNC_STAGE_PERIOD = 1 #amount of time to cache current sync stage in consensus service
CONSENSUS_CHECK_LOCAL_TPC_CAP_PERIOD = 60
MIN_GAS_PRICE_SYSTEM_UPDATE_PERIOD = 10 #This is also the amount of time between each min gas update with the PID system

#This is the amount of time we allow the network to additively sync root hashes. Any root hashes older than this
# amount of time from now will be synced via the consensus match method. Blocks can be up to 1000 seconds older than this
# and still be imported.
#After this time, the nodes will take the copy of the database that has the most stake.
ADDITIVE_SYNC_MODE_CUTOFF = 60*40
SYNC_STAGE_4_START_OFFSET = 60*5 # The number of seconds before the current time where we cut off the sync stage 4. If this was 0, then every 1000 seconds
                                # as we move to the next window, we would temporarily go to stage 3 and communication would stop.

PEER_STAKE_GONE_STALE_TIME_PERIOD = 60*5 # The amount of time that needs to pass before we re-update the peer stake from the
                                        # blockchain database or bootnode
SYNC_WITH_CONSENSUS_LOOP_TIME_PERIOD = 2 # The amount of time between each main loop of the syncer

# When doing a fast sync, it will try to sync up until this many seconds ago.
TIME_OFFSET_TO_FAST_SYNC_TO = 24*60*60

#
# Kademlia Constants
#

# number of bits per hop
KADEMLIA_BITS_PER_HOP = 8

# bucket size for kademlia routing table
KADEMLIA_BUCKET_SIZE = 16

# round trip message timout
KADEMLIA_REQUEST_TIMEOUT = 7.2

# Amount of time to consider a bucket idle
KADEMLIA_IDLE_BUCKET_REFRESH_INTERVAL = 3600

# Number of parallele `find_node` lookups that can be in progress
KADEMLIA_FIND_CONCURRENCY = 3

# Size of public keys in bits
KADEMLIA_PUBLIC_KEY_SIZE = 512

# Size of a node id in bits
KADEMLIA_ID_SIZE = 256

# Maximum node `id` for a kademlia node
KADEMLIA_MAX_NODE_ID = (2 ** KADEMLIA_ID_SIZE) - 1


# Reserved command length for the base `p2p` protocol
# - https://github.com/ethereum/devp2p/blob/master/rlpx.md#message-id-based-multiplexing
P2P_PROTOCOL_COMMAND_LENGTH = 16

# RLPx header data
RLPX_HEADER_DATA = b'\xc2\x80\x80'  # rlp.encode([0, 0])
