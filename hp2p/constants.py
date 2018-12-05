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

MAINNET_BOOTNODES = ()
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
#FAST_SYNC_CUTOFF_PERIOD = 60*60*24 #one day
#TODO.
FAST_SYNC_CUTOFF_PERIOD = 0 #testing
FAST_SYNC_NUM_CHAINS_TO_REQUEST = 5
ASK_BOOT_NODE_FOR_STAKE_CUTOFF_PERIOD = 60*24 #testing

CONSENSUS_SYNC_TIME_PERIOD = 5 #the amount of time between checking that we are in sync with peers
CONSENSUS_CHECK_MIN_GAS_SYSTEM_READY_TIME_PERIOD = 5
CONSENSUS_CHECK_CURRENT_SYNC_STAGE_PERIOD = 1 #amount of time to cache current sync stage in consensus service
CONSENSUS_CHECK_LOCAL_TPC_CAP_PERIOD = 60
MIN_GAS_PRICE_SYSTEM_SYNC_WITH_NETWORK_PERIOD = 5 #this should be set to 30 after testing
MIN_PEERS_TO_CALCULATE_NETWORK_TPC_CAP_AVG = 0 #This can only be set higher once the network is running. at the start this needs to be 0
MOVING_WINDOW_WHERE_HISTORICAL_ROOT_HASH_NOT_SYNCED = 60*5 #This is the amount of time we allow the network to sync new blocks between nodes.
                                                           #After this time, the nodes will take the copy of the database that has the most stake.

PEER_STAKE_GONE_STALE_TIME_PERIOD = 60 # The amount of time that needs to pass before we re-update the peer stake from the
                                        # blockchain database.

#DEVELOPMENT HELPERS
LOCAL_PEER_POOL_PATH = '/home/tommy/.local/share/helios/local_peer_pool'


#TESTING
PEER_STAKE_GONE_STALE_TIME_PERIOD = 5
MOVING_WINDOW_WHERE_HISTORICAL_ROOT_HASH_NOT_SYNCED = 60*60*24*10 #10 days


