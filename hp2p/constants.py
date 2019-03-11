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
)
ROPSTEN_BOOTNODES = ()
DISCOVERY_V5_BOOTNODES = ()

# Maximum peers number, we'll try to keep open connections up to this number of peers
DEFAULT_MAX_PEERS = 25

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


############
# NEW HELIOS
############
#the minimum number of peers to be connected to before consensus is ready.
MIN_SAFE_PEERS = 1
#the minimum amount of time to wait between loading historical root hash from database
LOCAL_ROOT_HASH_CHECK_MIN_TIME_PERIOD = 2
#if this amount of time passes, and none of the peers have a different block than ours, we delete the conflicblock
BLOCK_CONFLICT_RESOLUTION_PERIOD = 60
#the amount of time to wait between removing data from disconnected peers
CONSENUS_PEER_DISCONNECT_CHECK_PERIOD = 120
CONSENSUS_CHECK_READY_TIME_PERIOD = 2
FAST_SYNC_NUM_CHAINS_TO_REQUEST = 5
ASK_BOOT_NODE_FOR_STAKE_CUTOFF_PERIOD = 60*24 #testing

CONSENSUS_SYNC_TIME_PERIOD = 3 #the amount of time between checking that we are in sync with peers
CONSENSUS_CHECK_MIN_GAS_SYSTEM_READY_TIME_PERIOD = 5
CONSENSUS_CHECK_CURRENT_SYNC_STAGE_PERIOD = 1 #amount of time to cache current sync stage in consensus service
CONSENSUS_CHECK_LOCAL_TPC_CAP_PERIOD = 60
MIN_GAS_PRICE_SYSTEM_SYNC_WITH_NETWORK_PERIOD = 5 #this should be set to 30 after testing
MIN_PEERS_TO_CALCULATE_NETWORK_TPC_CAP_AVG = 0 #This might as well be left at 0, which will let the node calculate the tpc cap on its own until it connects to more nodes.

#This is the amount of time we allow the network to additively sync root hashes. Any root hashes older than this
# amount of time from now will be synced via the consensus match method. Blocks can be up to 1000 seconds older than this
# and still be imported.
#After this time, the nodes will take the copy of the database that has the most stake.
ADDITIVE_SYNC_MODE_CUTOFF = 60*40
SYNC_STAGE_4_START_OFFSET = 60*5 # The number of seconds before the current time where we cut off the sync stage 4. If this was 0, then every 1000 seconds
                                # as we move to the next window, we would temporarily go to stage 3 and communication would stop.

PEER_STAKE_GONE_STALE_TIME_PERIOD = 60*5 # The amount of time that needs to pass before we re-update the peer stake from the
                                        # blockchain database or bootnode
SYNC_WITH_CONSENSUS_LOOP_TIME_PERIOD = 1 # The amount of time between each main loop of the syncer

# When doing a fast sync, it will try to sync up until this many seconds ago.
TIME_OFFSET_TO_FAST_SYNC_TO = 24*60*60

#TESTING
PEER_STAKE_GONE_STALE_TIME_PERIOD = 5
#ADDITIVE_SYNC_MODE_CUTOFF = 60 * 60 * 24 * 10 #10 days


