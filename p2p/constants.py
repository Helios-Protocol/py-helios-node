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

# Types of LES Announce messages
LES_ANNOUNCE_SIMPLE = 1
LES_ANNOUNCE_SIGNED = 2

#MAINNET_BOOTNODES = (
#    'enode://b94bcd50daf3cc002b82da30220ac2349611eb75ea67def149c8190ace99389691d705049ec447f36cb819f6e5b6fcba341fe06cef2ca0819cc649c54fb2346e@127.0.0.1:30303',  # noqa: E501
#)
MAINNET_BOOTNODES = (
    'enode://a979fb575495b8d6db44f750317d0f4622bf4c2aa3365d6af7c284339968eef29b69ad0dce72a4d8db5ebb4968de0e3bec910127f134779fbcb0cb6d3331163c@127.0.0.1:30303',  # noqa: E501
)

# Maximum peers number, we'll try to keep open connections up to this number of peers
DEFAULT_MAX_PEERS = 25
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
NUM_CHAINS_TO_REQUEST = 5
ASK_BOOT_NODE_FOR_STAKE_CUTOFF_PERIOD = 60*24 #testing


CONSENSUS_SYNC_TIME_PERIOD = 5 #the amount of time between checking that we are in sync with peers
CONSENSUS_CHECK_MIN_GAS_SYSTEM_READY_TIME_PERIOD = 5
CONSENSUS_CHECK_LOCAL_TPC_CAP_PERIOD = 60
MIN_GAS_PRICE_SYSTEM_SYNC_WITH_NETWORK_PERIOD = 5 #this should be set to 30 after testing
MIN_PEERS_TO_CALCULATE_NETWORK_TPC_CAP_AVG = 0 #This can only be set higher once the network is running. at the start this needs to be 0
MOVING_WINDOW_WHERE_HISTORICAL_ROOT_HASH_NOT_SYNCED = 60*5

LOCAL_PEER_POOL_PATH = '/home/tommy/.local/share/trinity/local_peer_pool'

#switch to turn off upnp for local communication only
DO_UPNP = False


