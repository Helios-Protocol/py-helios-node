import asyncio
import collections
import contextlib
import logging
import operator
import random
import struct
import time
import json
import secrets

from abc import (
    ABC,
    abstractmethod
)

from typing import (
    Any,
    cast,
    Dict,
    Generator,
    Iterator,
    List,
    Sequence,
    TYPE_CHECKING,
    Tuple,
    Type,
)

import sha3

import rlp
from rlp import sedes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.constant_time import bytes_eq

from eth_utils import (
    decode_hex,
    encode_hex,
    to_tuple,
)

from eth_typing import BlockNumber, Hash32

from eth_keys import (
    datatypes,
    keys,
)

from evm.chains.mainnet import MAINNET_NETWORK_ID
from evm.constants import GENESIS_BLOCK_NUMBER
from evm.rlp.headers import BlockHeader
from evm.exceptions import (
    CanonicalHeadNotFound,        
)

from p2p import auth
from p2p import ecies
from p2p.discovery import DiscoveryProtocol
from p2p.kademlia import Address, Node
from p2p import protocol
from p2p.exceptions import (
    BadAckMessage,
    DecryptionError,
    HandshakeFailure,
    MalformedMessage,
    NoEligibleNodes,
    NoMatchingPeerCapabilities,
    OperationCancelled,
    PeerConnectionLost,
    RemoteDisconnected,
    UnexpectedMessage,
    UnknownProtocolCommand,
    UnreachablePeer,
)
from p2p.cancel_token import CancelToken
from p2p.service import BaseService
from p2p.utils import (
    get_devp2p_cmd_id,
    roundup_16,
    sxor,
    extract_wallet_verification_sender,
    create_wallet_verification_signature,
    validate_transaction_signature,
)
from p2p import eth
from p2p import hls
from p2p import les
from p2p.p2p_proto import (
    Disconnect,
    DisconnectReason,
    Hello,
    P2PProtocol,
    Ping,
    Pong,
)

from .constants import (
    CONN_IDLE_TIMEOUT,
    DEFAULT_MAX_PEERS,
    HEADER_LEN,
    MAC_LEN,
    LOCAL_PEER_POOL_PATH,
)

if TYPE_CHECKING:
    from trinity.db.header import BaseAsyncHeaderDB  # noqa: F401


async def handshake(remote: Node,
                    privkey: datatypes.PrivateKey,
                    peer_class: 'Type[BasePeer]',
                    chain,
                    chaindb,
                    chain_config, 
                    chain_head_db,
                    network_id: int,
                    token: CancelToken,
                    ) -> 'BasePeer':
    """Perform the auth and P2P handshakes with the given remote.

    Return an instance of the given peer_class (must be a subclass of BasePeer) connected to that
    remote in case both handshakes are successful and at least one of the sub-protocols supported
    by peer_class is also supported by the remote.

    Raises UnreachablePeer if we cannot connect to the peer or HandshakeFailure if the remote
    disconnects before completing the handshake or if none of the sub-protocols supported by us is
    also supported by the remote.
    """
    try:
        (aes_secret,
         mac_secret,
         egress_mac,
         ingress_mac,
         reader,
         writer
         ) = await auth.handshake(remote, privkey, token)
    except (ConnectionRefusedError, OSError) as e:
        raise UnreachablePeer(e)
    peer = peer_class(
        remote=remote, privkey=privkey, reader=reader, writer=writer,
        aes_secret=aes_secret, mac_secret=mac_secret, egress_mac=egress_mac,
        ingress_mac=ingress_mac, chaindb=chaindb, network_id=network_id,
        chain_config = chain_config, chain_head_db = chain_head_db, chain = chain)
    await peer.do_p2p_handshake()
    await peer.do_sub_proto_handshake()
    return peer


class BasePeer(BaseService):
    logger = logging.getLogger("p2p.peer.Peer")
    conn_idle_timeout = CONN_IDLE_TIMEOUT
    # Must be defined in subclasses. All items here must be Protocol classes representing
    # different versions of the same P2P sub-protocol (e.g. ETH, LES, etc).
    _supported_sub_protocols: List[Type[protocol.Protocol]] = []
    # FIXME: Must be configurable.
    listen_port = 30303
    # Will be set upon the successful completion of a P2P handshake.
    sub_proto: protocol.Protocol = None

    def __init__(self,
                 remote: Node,
                 privkey: datatypes.PrivateKey,
                 reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter,
                 aes_secret: bytes,
                 mac_secret: bytes,
                 egress_mac: sha3.keccak_256,
                 ingress_mac: sha3.keccak_256,
                 chain,
                 chaindb,
                 network_id: int,
                 chain_config,
                 chain_head_db,
                 inbound: bool = False,
                 ) -> None:
        super().__init__()
        self.chain_config = chain_config
        self.chain_head_db = chain_head_db
        self.remote = remote
        self.privkey = privkey
        self.reader = reader
        self.writer = writer
        self.chaindb = chaindb
        self.base_protocol = P2PProtocol(self)
        self.chain = chain
        self.network_id = network_id
        self.inbound = inbound
        self._subscribers: List['asyncio.Queue[PEER_MSG_TYPE]'] = []

        self.egress_mac = egress_mac
        self.ingress_mac = ingress_mac
        # FIXME: Yes, the encryption is insecure, see: https://github.com/ethereum/devp2p/issues/32
        iv = b"\x00" * 16
        aes_cipher = Cipher(algorithms.AES(aes_secret), modes.CTR(iv), default_backend())
        self.aes_enc = aes_cipher.encryptor()
        self.aes_dec = aes_cipher.decryptor()
        mac_cipher = Cipher(algorithms.AES(mac_secret), modes.ECB(), default_backend())
        self.mac_enc = mac_cipher.encryptor().update

    @abstractmethod
    async def send_sub_proto_handshake(self):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    async def process_sub_proto_handshake(
            self, cmd: protocol.Command, msg: protocol._DecodedMsgType) -> None:
        raise NotImplementedError("Must be implemented by subclasses")

    def add_subscriber(self, subscriber: 'asyncio.Queue[PEER_MSG_TYPE]') -> None:
        self._subscribers.append(subscriber)

    def remove_subscriber(self, subscriber: 'asyncio.Queue[PEER_MSG_TYPE]') -> None:
        if subscriber in self._subscribers:
            self._subscribers.remove(subscriber)

    async def do_sub_proto_handshake(self):
        """Perform the handshake for the sub-protocol agreed with the remote peer.

        Raises HandshakeFailure if the handshake is not successful.
        """
        await self.send_sub_proto_handshake()
        cmd, msg = await self.read_msg()
        if isinstance(cmd, Disconnect):
            # Peers sometimes send a disconnect msg before they send the sub-proto handshake.
            raise HandshakeFailure(
                "{} disconnected before completing sub-proto handshake: {}".format(
                    self, msg['reason_name']))
        await self.process_sub_proto_handshake(cmd, msg)
        
        #After the sub_proto handshake, the peer will send back a signed message containing the wallet address
        cmd, msg = await self.read_msg()
        if isinstance(cmd, Disconnect):
            # Peers sometimes send a disconnect msg before they send the sub-proto handshake.
            raise HandshakeFailure(
                "{} disconnected before completing wallet address verification: {}".format(
                    self, msg['reason_name']))
        await self.process_sub_proto_wallet_address_verification(cmd, msg)
        
        self.logger.debug("Finished %s handshake with %s", self.sub_proto, self.remote)

    async def do_p2p_handshake(self):
        """Perform the handshake for the P2P base protocol.

        Raises HandshakeFailure if the handshake is not successful.
        """
        self.base_protocol.send_handshake()

        try:
            cmd, msg = await self.read_msg()
        except rlp.DecodingError:
            raise HandshakeFailure("Got invalid rlp data during handshake")

        if isinstance(cmd, Disconnect):
            # Peers sometimes send a disconnect msg before they send the initial P2P handshake.
            raise HandshakeFailure("{} disconnected before completing handshake: {}".format(
                self, msg['reason_name']))
        self.process_p2p_handshake(cmd, msg)

    @property
    async def genesis(self) -> BlockHeader:
        genesis_hash = await self.wait(
            self.chaindb.coro_get_canonical_block_hash(BlockNumber(GENESIS_BLOCK_NUMBER)))
        return await self.wait(self.chaindb.coro_get_block_header_by_hash(genesis_hash))

    @property
    async def _local_chain_info(self) -> 'ChainInfo':
        
        node_type = self.chain_config.node_type
        node_wallet_address = self.chain_config.node_wallet_address
        chain_head_root_hashes = await self.chain_head_db.coro_get_historical_root_hashes()

        return ChainInfo(
            node_type=node_type,
            node_wallet_address=node_wallet_address,
            chain_head_root_hashes = chain_head_root_hashes
        )

    @property
    def capabilities(self) -> List[Tuple[str, int]]:
        return [(klass.name, klass.version) for klass in self._supported_sub_protocols]

    def get_protocol_command_for(self, msg: bytes) -> protocol.Command:
        """Return the Command corresponding to the cmd_id encoded in the given msg."""
        cmd_id = get_devp2p_cmd_id(msg)
        self.logger.debug("Got msg with cmd_id: %s", cmd_id)
        if cmd_id < self.base_protocol.cmd_length:
            proto = self.base_protocol
        elif cmd_id < self.sub_proto.cmd_id_offset + self.sub_proto.cmd_length:
            proto = self.sub_proto  # type: ignore
        else:
            raise UnknownProtocolCommand("No protocol found for cmd_id {}".format(cmd_id))
        return proto.cmd_by_id[cmd_id]

    async def read(self, n: int) -> bytes:
        self.logger.debug("Waiting for %s bytes from %s", n, self.remote)
        try:
            return await self.wait_first(
                self.reader.readexactly(n), timeout=self.conn_idle_timeout)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError) as e:
            raise PeerConnectionLost(repr(e))

    def close(self):
        """Close this peer's reader/writer streams.

        This will cause the peer to stop in case it is running.

        If the streams have already been closed, do nothing.
        """
        if self.reader.at_eof():
            return
        self.reader.feed_eof()
        self.writer.close()

    async def _cleanup(self):
        self.close()

    async def _run(self):
        while True:
            try:
                cmd, msg = await self.read_msg()
            except (PeerConnectionLost, TimeoutError) as e:
                self.logger.info(
                    "%s stopped responding (%s), disconnecting", self.remote, repr(e))
                return

            try:
                self.process_msg(cmd, msg)
            except RemoteDisconnected as e:
                self.logger.debug("%s disconnected: %s", self, e)
                return

    async def read_msg(self) -> Tuple[protocol.Command, protocol._DecodedMsgType]:
        header_data = await self.read(HEADER_LEN + MAC_LEN)
        header = self.decrypt_header(header_data)
        frame_size = self.get_frame_size(header)
        # The frame_size specified in the header does not include the padding to 16-byte boundary,
        # so need to do this here to ensure we read all the frame's data.
        read_size = roundup_16(frame_size)
        frame_data = await self.read(read_size + MAC_LEN)
        msg = self.decrypt_body(frame_data, frame_size)
        cmd = self.get_protocol_command_for(msg)
        # NOTE: This used to be a bottleneck but it doesn't seem to be so anymore. If we notice
        # too much time is being spent on this again, we need to consider running this in a
        # ProcessPoolExecutor(). Need to make sure we don't use all CPUs in the machine for that,
        # though, otherwise asyncio's event loop can't run and we can't keep up with other peers.
        decoded_msg = cmd.decode(msg)
        self.logger.debug("Successfully decoded %s msg: %s", cmd, decoded_msg)
        return cmd, decoded_msg

    def handle_p2p_msg(self, cmd: protocol.Command, msg: protocol._DecodedMsgType) -> None:
        """Handle the base protocol (P2P) messages."""
        if isinstance(cmd, Disconnect):
            msg = cast(Dict[str, Any], msg)
            raise RemoteDisconnected(msg['reason_name'])
        elif isinstance(cmd, Ping):
            self.base_protocol.send_pong()
        elif isinstance(cmd, Pong):
            # Currently we don't do anything when we get a pong, but eventually we should
            # update the last time we heard from a peer in our DB (which doesn't exist yet).
            pass
        else:
            raise UnexpectedMessage("Unexpected msg: {} ({})".format(cmd, msg))

    def handle_sub_proto_msg(self, cmd: protocol.Command, msg: protocol._DecodedMsgType) -> None:
        #lets catch and handle the wallet address verification
        if isinstance(cmd, hls.GetWalletAddressVerification):
            msg = cast(Dict[str, Any], msg)
            self.send_wallet_address_verification(msg['primary_salt'])
        elif self._subscribers:
            for subscriber in self._subscribers:
                subscriber.put_nowait((self, cmd, msg))
        else:
            self.logger.warn("Peer %s has no subscribers, discarding %s msg", self, cmd)

    def process_msg(self, cmd: protocol.Command, msg: protocol._DecodedMsgType) -> None:
        if cmd.is_base_protocol:
            self.handle_p2p_msg(cmd, msg)
        else:
            self.handle_sub_proto_msg(cmd, msg)

    def process_p2p_handshake(self, cmd: protocol.Command, msg: protocol._DecodedMsgType) -> None:
        msg = cast(Dict[str, Any], msg)
        if not isinstance(cmd, Hello):
            self.disconnect(DisconnectReason.other)
            raise HandshakeFailure("Expected a Hello msg, got {}, disconnecting".format(cmd))
        remote_capabilities = msg['capabilities']
        try:
            self.sub_proto = self.select_sub_protocol(remote_capabilities)
        except NoMatchingPeerCapabilities:
            self.disconnect(DisconnectReason.useless_peer)
            raise HandshakeFailure(
                "No matching capabilities between us ({}) and {} ({}), disconnecting".format(
                    self.capabilities, self.remote, remote_capabilities))
        self.logger.debug(
            "Finished P2P handshake with %s, using sub-protocol %s",
            self.remote, self.sub_proto)

    def encrypt(self, header: bytes, frame: bytes) -> bytes:
        if len(header) != HEADER_LEN:
            raise ValueError("Unexpected header length: {}".format(len(header)))

        header_ciphertext = self.aes_enc.update(header)
        mac_secret = self.egress_mac.digest()[:HEADER_LEN]
        self.egress_mac.update(sxor(self.mac_enc(mac_secret), header_ciphertext))
        header_mac = self.egress_mac.digest()[:HEADER_LEN]

        frame_ciphertext = self.aes_enc.update(frame)
        self.egress_mac.update(frame_ciphertext)
        fmac_seed = self.egress_mac.digest()[:HEADER_LEN]

        mac_secret = self.egress_mac.digest()[:HEADER_LEN]
        self.egress_mac.update(sxor(self.mac_enc(mac_secret), fmac_seed))
        frame_mac = self.egress_mac.digest()[:HEADER_LEN]

        return header_ciphertext + header_mac + frame_ciphertext + frame_mac

    def decrypt_header(self, data: bytes) -> bytes:
        if len(data) != HEADER_LEN + MAC_LEN:
            raise ValueError("Unexpected header length: {}".format(len(data)))

        header_ciphertext = data[:HEADER_LEN]
        header_mac = data[HEADER_LEN:]
        mac_secret = self.ingress_mac.digest()[:HEADER_LEN]
        aes = self.mac_enc(mac_secret)[:HEADER_LEN]
        self.ingress_mac.update(sxor(aes, header_ciphertext))
        expected_header_mac = self.ingress_mac.digest()[:HEADER_LEN]
        if not bytes_eq(expected_header_mac, header_mac):
            raise DecryptionError('Invalid header mac')
        return self.aes_dec.update(header_ciphertext)

    def decrypt_body(self, data: bytes, body_size: int) -> bytes:
        read_size = roundup_16(body_size)
        if len(data) < read_size + MAC_LEN:
            raise ValueError('Insufficient body length; Got {}, wanted {}'.format(
                len(data), (read_size + MAC_LEN)))

        frame_ciphertext = data[:read_size]
        frame_mac = data[read_size:read_size + MAC_LEN]

        self.ingress_mac.update(frame_ciphertext)
        fmac_seed = self.ingress_mac.digest()[:MAC_LEN]
        self.ingress_mac.update(sxor(self.mac_enc(fmac_seed), fmac_seed))
        expected_frame_mac = self.ingress_mac.digest()[:MAC_LEN]
        if not bytes_eq(expected_frame_mac, frame_mac):
            raise DecryptionError('Invalid frame mac')
        return self.aes_dec.update(frame_ciphertext)[:body_size]

    def get_frame_size(self, header: bytes) -> int:
        # The frame size is encoded in the header as a 3-byte int, so before we unpack we need
        # to prefix it with an extra byte.
        encoded_size = b'\x00' + header[:3]
        (size,) = struct.unpack(b'>I', encoded_size)
        return size

    def send(self, header: bytes, body: bytes) -> None:
        cmd_id = rlp.decode(body[:1], sedes=sedes.big_endian_int)
        self.logger.debug("Sending msg with cmd_id: %s", cmd_id)
        self.writer.write(self.encrypt(header, body))

    def disconnect(self, reason: DisconnectReason) -> None:
        """Send a disconnect msg to the remote node and stop this Peer.

        :param reason: An item from the DisconnectReason enum.
        """
        if not isinstance(reason, DisconnectReason):
            self.logger.debug("Disconnecting from remote peer; reason: %s", reason.value)
            raise ValueError(
                "Reason must be an item of DisconnectReason, got {}".format(reason))
        self.base_protocol.send_disconnect(reason.value)
        self.close()

    def select_sub_protocol(self, remote_capabilities: List[Tuple[bytes, int]]
                            ) -> protocol.Protocol:
        """Select the sub-protocol to use when talking to the remote.

        Find the highest version of our supported sub-protocols that is also supported by the
        remote and stores an instance of it (with the appropriate cmd_id offset) in
        self.sub_proto.

        Raises NoMatchingPeerCapabilities if none of our supported protocols match one of the
        remote's protocols.
        """
        matching_capabilities = set(self.capabilities).intersection(remote_capabilities)
        if not matching_capabilities:
            raise NoMatchingPeerCapabilities()
        _, highest_matching_version = max(matching_capabilities, key=operator.itemgetter(1))
        offset = self.base_protocol.cmd_length
        for proto_class in self._supported_sub_protocols:
            if proto_class.version == highest_matching_version:
                return proto_class(self, offset)
        raise NoMatchingPeerCapabilities()

    def __str__(self):
        return "{} {}".format(self.__class__.__name__, self.remote)


class LESPeer(BasePeer):
    max_headers_fetch = les.MAX_HEADERS_FETCH
    _supported_sub_protocols = [les.LESProtocol, les.LESProtocolV2]
    sub_proto: les.LESProtocol = None
    head_info: les.HeadInfo = None

    async def send_sub_proto_handshake(self):
        self.sub_proto.send_handshake(await self._local_chain_info)

    async def process_sub_proto_handshake(
            self, cmd: protocol.Command, msg: protocol._DecodedMsgType) -> None:
        if not isinstance(cmd, (les.Status, les.StatusV2)):
            self.disconnect(DisconnectReason.other)
            raise HandshakeFailure(
                "Expected a LES Status msg, got {}, disconnecting".format(cmd))
        msg = cast(Dict[str, Any], msg)
        if msg['networkId'] != self.network_id:
            self.disconnect(DisconnectReason.other)
            raise HandshakeFailure(
                "{} network ({}) does not match ours ({}), disconnecting".format(
                    self, msg['networkId'], self.network_id))
        genesis = await self.genesis
        if msg['genesisHash'] != genesis.hash:
            self.disconnect(DisconnectReason.other)
            raise HandshakeFailure(
                "{} genesis ({}) does not match ours ({}), disconnecting".format(
                    self, encode_hex(msg['genesisHash']), genesis.hex_hash))
        # TODO: Disconnect if the remote doesn't serve headers.
        self.head_info = cmd.as_head_info(msg)


class ETHPeer(BasePeer):
    _supported_sub_protocols = [eth.ETHProtocol]
    sub_proto: eth.ETHProtocol = None
    head_td: int = None
    head_hash: Hash32 = None

    async def send_sub_proto_handshake(self):
        chain_info = await self._local_chain_info
        self.sub_proto.send_handshake(chain_info)

    async def process_sub_proto_handshake(
            self, cmd: protocol.Command, msg: protocol._DecodedMsgType) -> None:
        if not isinstance(cmd, eth.Status):
            self.disconnect(DisconnectReason.other)
            raise HandshakeFailure(
                "Expected a ETH Status msg, got {}, disconnecting".format(cmd))
        msg = cast(Dict[str, Any], msg)
        if msg['network_id'] != self.network_id:
            self.disconnect(DisconnectReason.other)
            raise HandshakeFailure(
                "{} network ({}) does not match ours ({}), disconnecting".format(
                    self, msg['network_id'], self.network_id))
#        genesis = await self.genesis
#        if msg['genesis_hash'] != genesis.hash:
#            self.disconnect(DisconnectReason.other)
#            raise HandshakeFailure(
#                "{} genesis ({}) does not match ours ({}), disconnecting".format(
#                    self, encode_hex(msg['genesis_hash']), genesis.hex_hash))
        #self.head_td = msg['td']
        #self.head_hash = msg['best_hash']
        
        
class HLSPeer(BasePeer):
    logger = logging.getLogger("p2p.peer.HLSPeer")
    _supported_sub_protocols = [hls.HLSProtocol]
    sub_proto: hls.HLSProtocol = None
    #stake: int = None
    stake: int = 1000 #testing
    wallet_address = None
    local_salt = None
    peer_salt = None
    
    async def send_sub_proto_handshake(self):
        local_salt = secrets.token_bytes(32)
        chain_info = await self._local_chain_info
        self.sub_proto.send_handshake(chain_info, local_salt)
        self.local_salt = local_salt

    async def process_sub_proto_handshake(
            self, cmd: protocol.Command, msg: protocol._DecodedMsgType) -> None:
        if not isinstance(cmd, hls.Status):
            self.disconnect(DisconnectReason.other)
            raise HandshakeFailure(
                "Expected a HLS Status msg, got {}, disconnecting".format(cmd))
        msg = cast(Dict[str, Any], msg)
        if msg['network_id'] != self.network_id:
            self.disconnect(DisconnectReason.other)
            raise HandshakeFailure(
                "{} network ({}) does not match ours ({}), disconnecting".format(
                    self, msg['network_id'], self.network_id))
        self.node_type = msg['node_type']
        #self.wallet_address = msg['wallet_address']
        self.chain_head_root_hashes = msg['chain_head_root_hashes']
        #TODO: need to lookup their stake
        #TODO: send another handshake that gaurantees their wallet address. We shouldnt even ask for it here...
        self.send_wallet_address_verification(msg['salt'])
        
    def send_sub_proto_wallet_address_verification(self):
        salt = secrets.token_bytes(32)
        self.sub_proto.send_get_wallet_address_verification(salt)
        self.primary_salt = salt
    
    async def process_sub_proto_wallet_address_verification(
            self, cmd: protocol.Command, msg: protocol._DecodedMsgType) -> None:
        if not isinstance(cmd, hls.WalletAddressVerification):
            self.disconnect(DisconnectReason.other)
            raise HandshakeFailure(
                "Expected a HLS WalletAddressVerification msg, got {}, disconnecting".format(cmd))
        msg = cast(Dict[str, Any], msg)
        #make sure the salt they replied with is the salt we sent:
        if msg['salt'] != self.local_salt:
            raise HandshakeFailure("The peer replied with a signed message using the wrong salt")
            
        validate_transaction_signature(msg['salt'], msg['v'], msg['r'], msg['s'])

        self.wallet_address = extract_wallet_verification_sender(msg['salt'], msg['v'], msg['r'], msg['s'])
        try:
            self.stake = await self.chain.coro_get_mature_stake(self.wallet_address)
        except CanonicalHeadNotFound:
            self.stake = None
        #self.logger.debug("Recieved valid wallet address verification for wallet address {}".format(self.wallet_address))
        
    #note, when we receive an address verification message, we have to verify that the salt they send back equals local salt
    def send_wallet_address_verification(self, salt):
        v, r, s = create_wallet_verification_signature(salt, self.chain_config.node_private_helios_key)
        self.sub_proto.send_wallet_address_verification(salt, v, r, s)
        self.peer_salt = salt
        #self.logger.debug("sending wallet address verification for wallet {}".format(self.chain_config.node_wallet_address))
        
        
class PeerPoolSubscriber(ABC):
    _msg_queue: 'asyncio.Queue[PEER_MSG_TYPE]' = None

    @abstractmethod
    def register_peer(self, peer: BasePeer) -> None:
        raise NotImplementedError("Must be implemented by subclasses")

    @property
    def msg_queue(self) -> 'asyncio.Queue[PEER_MSG_TYPE]':
        if self._msg_queue is None:
            self._msg_queue = asyncio.Queue(maxsize=10000)
        return self._msg_queue

    @contextlib.contextmanager
    def subscribe(self, peer_pool: 'PeerPool') -> Iterator[None]:
        peer_pool.subscribe(self)
        try:
            yield
        finally:
            peer_pool.unsubscribe(self)


class PeerPool(BaseService):
    """
    PeerPool maintains connections to up-to max_peers on a given network.
    """
    logger = logging.getLogger("p2p.peer.PeerPool")
    _connect_loop_sleep = 2
    _report_interval = 60
    _discovery_lookup_running = asyncio.Lock()
    _discovery_last_lookup: float = 0
    _discovery_lookup_interval: int = 30

    def __init__(self,
                 peer_class: Type[BasePeer],
                 chain,
                 chaindb,
                 network_id: int,
                 privkey: datatypes.PrivateKey,
                 discovery: DiscoveryProtocol,
                 chain_config,
                 chain_head_db,
                 max_peers: int = DEFAULT_MAX_PEERS,
                 ) -> None:
        super().__init__()
        self.chain_config = chain_config
        self.chain_head_db = chain_head_db
        self.peer_class = peer_class
        self.chain = chain
        self.chaindb = chaindb
        self.network_id = network_id
        self.privkey = privkey
        self.discovery = discovery
        self.max_peers = max_peers
        self.connected_nodes: Dict[Node, BasePeer] = {}
        self._subscribers: List[PeerPoolSubscriber] = []

    def __len__(self):
        return len(self.connected_nodes)

    @property
    def is_full(self) -> bool:
        return len(self) >= self.max_peers

    def get_nodes_to_connect(self) -> Generator[Node, None, None]:
        yield from self.discovery.get_random_nodes(self.max_peers)

    def subscribe(self, subscriber: PeerPoolSubscriber) -> None:
        self._subscribers.append(subscriber)
        for peer in self.connected_nodes.values():
            subscriber.register_peer(peer)
            peer.add_subscriber(subscriber.msg_queue)

    def unsubscribe(self, subscriber: PeerPoolSubscriber) -> None:
        if subscriber in self._subscribers:
            self._subscribers.remove(subscriber)
        for peer in self.connected_nodes.values():
            peer.remove_subscriber(subscriber.msg_queue)

    def start_peer(self, peer):
        asyncio.ensure_future(peer.run(finished_callback=self._peer_finished))
        self.add_peer(peer)

    def add_peer(self, peer):
        self.logger.debug('Adding peer (%s) ...', str(peer))
        self.connected_nodes[peer.remote] = peer
        self.logger.debug('Number of peers: %d', len(self.connected_nodes))
        for subscriber in self._subscribers:
            subscriber.register_peer(peer)
            peer.add_subscriber(subscriber.msg_queue)

    async def _run(self) -> None:
        self.logger.info("Running PeerPool...")
        asyncio.ensure_future(self._periodically_report_stats())
        while not self.cancel_token.triggered:
            await self.maybe_connect_to_more_peers()
            # Wait self._connect_loop_sleep seconds, unless we're asked to stop.
            await self.wait_first(asyncio.sleep(self._connect_loop_sleep))

    async def stop_all_peers(self) -> None:
        self.logger.info("Stopping all peers ...")
        await asyncio.gather(
            *[peer.cancel() for peer in self.connected_nodes.values()])

    async def _cleanup(self) -> None:
        await self.stop_all_peers()

    async def connect(self, remote: Node) -> BasePeer:
        """
        Connect to the given remote and return a Peer instance when successful.
        Returns None if the remote is unreachable, times out or is useless.
        """
        if remote in self.connected_nodes:
            self.logger.debug("Skipping %s; already connected to it", remote)
            return None
        expected_exceptions = (
            HandshakeFailure,
            PeerConnectionLost,
            TimeoutError,
            UnreachablePeer,
            MalformedMessage,
        )
        try:
            self.logger.debug("Connecting to %s...", remote)
            # We use self.wait() as well as passing our CancelToken to handshake() as a workaround
            # for https://github.com/ethereum/py-evm/issues/670.
            peer = await self.wait(
                handshake(
                    remote, self.privkey, self.peer_class, self.chain, self.chaindb, self.chain_config, self.chain_head_db, self.network_id,
                    self.cancel_token))

            return peer
        except OperationCancelled:
            # Pass it on to instruct our main loop to stop.
            raise
        except BadAckMessage:
            # TODO: This is kept separate from the `expected_exceptions` to be
            # sure that we aren't silencing an error in our authentication
            # code.
            self.logger.info('Got bad Ack during peer connection')
            # We intentionally log this twice, once in INFO to be sure we don't
            # forget about this and once in DEBUG which includes the stack
            # trace.
            self.logger.debug('Got bad Ack during peer connection', exc_info=True)
        except expected_exceptions as e:
            self.logger.debug("Could not complete handshake with %s: %s", remote, repr(e))
        except Exception:
            self.logger.exception("Unexpected error during auth/p2p handshake with %s", remote)
        return None

    async def maybe_lookup_random_node(self) -> None:
        if self._discovery_last_lookup + self._discovery_lookup_interval > time.time():
            return
        elif self._discovery_lookup_running.locked():
            self.logger.debug("Node discovery lookup already in progress, not running another")
            return
        async with self._discovery_lookup_running:
            # This method runs in the background, so we must catch OperationCancelled here
            # otherwise asyncio will warn that its exception was never retrieved.
            try:
                await self.discovery.lookup_random(self.cancel_token)
            except OperationCancelled:
                pass
            finally:
                self._discovery_last_lookup = time.time()

    async def maybe_connect_to_more_peers(self) -> None:
        """Connect to more peers if we're not yet maxed out to max_peers"""
        num_connected_nodes = len(self.connected_nodes)
        if self.is_full:
            self.logger.debug(
                "Already connected to %s peers: %s; sleeping",
                num_connected_nodes,
                [remote for remote in self.connected_nodes],
            )
            return

        asyncio.ensure_future(self.maybe_lookup_random_node())

        await self._connect_to_nodes(self.get_nodes_to_connect())

        # In some cases (e.g ROPSTEN or private testnets), the discovery table might be full of
        # bad peers so if we can't connect to any peers we try a random bootstrap node as well.
        if not self.peers:
            await self._connect_to_nodes(self._get_random_bootnode())

    def _get_random_bootnode(self) -> Generator[Node, None, None]:
        if self.discovery.bootstrap_nodes:
            yield random.choice(self.discovery.bootstrap_nodes)
        else:
            self.logger.warning('No bootnodes available')

    async def _connect_to_nodes(self, nodes: Generator[Node, None, None]) -> None:
        for node in nodes:
            # TODO: Consider changing connect() to raise an exception instead of returning None,
            # as discussed in
            # https://github.com/ethereum/py-evm/pull/139#discussion_r152067425
            peer = await self.connect(node)

            if peer is None:
                continue
            elif self.is_full:
                self.logger.debug("Peer pool is full: disconnecting from %s", peer)
                peer.disconnect(DisconnectReason.too_many_peers)
                break
            else:
                self.logger.info("Successfully connected to %s", peer)
                self.start_peer(peer)

    def _peer_finished(self, peer: BaseService) -> None:
        """Remove the given peer from our list of connected nodes.
        This is passed as a callback to be called when a peer finishes.
        """
        peer = cast(BasePeer, peer)
        if peer.remote in self.connected_nodes:
            self.connected_nodes.pop(peer.remote)

    @property
    def peers(self) -> List[BasePeer]:
        peers = list(self.connected_nodes.values())
        # Shuffle the list of peers so that dumb callsites are less likely to send all requests to
        # a single peer even if they always pick the first one from the list.
        random.shuffle(peers)
        return peers

    async def get_random_peer(self) -> BasePeer:
        while not self.peers:
            self.logger.debug("No connected peers, sleeping a bit")
            await asyncio.sleep(0.5)
        return random.choice(self.peers)

    async def _periodically_report_stats(self):
        while self.is_running:
            inbound_peers = len(
                [peer for peer in self.connected_nodes.values() if peer.inbound])
            self.logger.info("Connected peers: %d inbound, %d outbound",
                             inbound_peers, (len(self.connected_nodes) - inbound_peers))
            self.logger.debug("== Peer details == ")
            for peer in self.connected_nodes.values():
                subscribers = len(peer._subscribers)
                longest_queue = 0
                if subscribers:
                    longest_queue = max(queue.qsize() for queue in peer._subscribers)
                self.logger.debug(
                    "%s: running=%s, subscribers=%d, longest_subscriber_queue=%s",
                    peer, peer.is_running, subscribers, longest_queue)
            self.logger.debug("== End peer details == ")
            try:
                await self.wait(asyncio.sleep(self._report_interval))
            except OperationCancelled:
                break


DEFAULT_PREFERRED_NODES: Dict[int, Tuple[Node, ...]] = {
    MAINNET_NETWORK_ID: (
        Node(keys.PublicKey(decode_hex("1118980bf48b0a3640bdba04e0fe78b1add18e1cd99bf22d53daac1fd9972ad650df52176e7c7d89d1114cfef2bc23a2959aa54998a46afcf7d91809f0855082")),  # noqa: E501
             Address("52.74.57.123", 30303, 30303)),
        Node(keys.PublicKey(decode_hex("78de8a0916848093c73790ead81d1928bec737d565119932b98c6b100d944b7a95e94f847f689fc723399d2e31129d182f7ef3863f2b4c820abbf3ab2722344d")),  # noqa: E501
             Address("191.235.84.50", 30303, 30303)),
    ),

}


        
class LocalNodesPeerPool(PeerPool):
    """
    A PeerPool that uses a hard-coded list of remote nodes to connect to.

    The node discovery v4 protocol is terrible at finding LES nodes, so for now
    we hard-code some nodes that seem to have a good uptime.
    """
    _local_peer_pool = None
        
    def _get_random_bootnode(self) -> Generator[Node, None, None]:
        # We don't have a DiscoveryProtocol with bootnodes, so just return one of our regular
        # hardcoded nodes.
        options = list(self.get_nodes_to_connect())
        if options:
            yield random.choice(options)
        else:
            self.logger.warning('No bootnodes available')

    async def maybe_lookup_random_node(self) -> None:
        # Do nothing as we don't have a DiscoveryProtocol
        pass

    def get_nodes_to_connect(self) -> Generator[Node, None, None]:
        nodes = self.local_peer_pool
        random.shuffle(nodes)
        for node in nodes:
            yield node      
      
    @classmethod
    def load_peers_from_file(self):
        path = LOCAL_PEER_POOL_PATH
        #load existing pool
        with open(path, 'r') as peer_file:
            existing_peers_raw = peer_file.read()
            existing_peers = json.loads(existing_peers_raw)
        return existing_peers
    
    #save as [public_key,ip,udp_port,tcp_port]
    @property
    def local_peer_pool(self):
        if self._local_peer_pool is None:
            
            existing_peers = self.load_peers_from_file()
            
            #self.logger.debug('loaded local peer nodes: {}'.format(existing_peers_raw))
            #we have to change it into the expected form
            peer_pool = []
            for i, peer in enumerate(existing_peers):
                if peer[0] != self.privkey.public_key.to_hex():
                    peer_pool.append(Node(keys.PublicKey(decode_hex(peer[0])),Address(peer[1], peer[2], peer[3])))
            self._local_peer_pool = peer_pool
            
        return self._local_peer_pool
            
        
    
class HardCodedNodesPeerPool(PeerPool):
    """
    A PeerPool that uses a hard-coded list of remote nodes to connect to.

    The node discovery v4 protocol is terrible at finding LES nodes, so for now
    we hard-code some nodes that seem to have a good uptime.
    """

    def _get_random_bootnode(self) -> Generator[Node, None, None]:
        # We don't have a DiscoveryProtocol with bootnodes, so just return one of our regular
        # hardcoded nodes.
        options = list(self.get_nodes_to_connect())
        if options:
            yield random.choice(options)
        else:
            self.logger.warning('No bootnodes available')

    async def maybe_lookup_random_node(self) -> None:
        # Do nothing as we don't have a DiscoveryProtocol
        pass

    def get_nodes_to_connect(self) -> Generator[Node, None, None]:
        if self.network_id in DEFAULT_PREFERRED_NODES:
            nodes = list(DEFAULT_PREFERRED_NODES[self.network_id])
        else:
            raise ValueError("Unknown network_id: {}".format(self.network_id))

        random.shuffle(nodes)
        for node in nodes:
            yield node


class PreferredNodePeerPool(PeerPool):
    """
    A PeerPool which has a list of preferred nodes which it will prioritize
    using before going to the discovery protocol to find nodes.  Each preferred
    node can only be used once every preferred_node_recycle_time seconds.
    """
    preferred_nodes: Sequence[Node] = None
    preferred_node_recycle_time: int = 300
    _preferred_node_tracker: Dict[Node, float] = None

    def __init__(self,
                 peer_class: Type[BasePeer],
                 headerdb: 'BaseAsyncHeaderDB',
                 network_id: int,
                 privkey: datatypes.PrivateKey,
                 discovery: DiscoveryProtocol,
                 max_peers: int = DEFAULT_MAX_PEERS,
                 preferred_nodes: Sequence[Node] = None,
                 ) -> None:
        super().__init__(
            peer_class,
            headerdb,
            network_id,
            privkey,
            discovery,
            max_peers=max_peers,
        )

        if preferred_nodes is not None:
            self.preferred_nodes = preferred_nodes
        elif network_id in DEFAULT_PREFERRED_NODES:
            self.preferred_nodes = DEFAULT_PREFERRED_NODES[network_id]
        else:
            self.logger.debug('PreferredNodePeerPool operating with no preferred nodes')
            self.preferred_nodes = tuple()

        self._preferred_node_tracker = collections.defaultdict(lambda: 0)

    @to_tuple
    def _get_eligible_preferred_nodes(self) -> Generator[Node, None, None]:
        """
        Return nodes from the preferred_nodes which have not been used within
        the last preferred_node_recycle_time
        """
        for node in self.preferred_nodes:
            last_used = self._preferred_node_tracker[node]
            if time.time() - last_used > self.preferred_node_recycle_time:
                yield node

    def _get_random_preferred_node(self) -> Node:
        """
        Return a random node from the preferred list.
        """
        eligible_nodes = self._get_eligible_preferred_nodes()
        if not eligible_nodes:
            raise NoEligibleNodes("No eligible preferred nodes available")
        node = random.choice(eligible_nodes)
        return node

    def _get_random_bootnode(self) -> Generator[Node, None, None]:
        """
        Return a single node to bootstrap, preferring nodes from the preferred list.
        """
        try:
            node = self._get_random_preferred_node()
            self._preferred_node_tracker[node] = time.time()
            yield node
        except NoEligibleNodes:
            yield from super()._get_random_bootnode()

    def get_nodes_to_connect(self) -> Generator[Node, None, None]:
        """
        Return up to `max_peers` nodes, preferring nodes from the preferred list.
        """
        preferred_nodes = self._get_eligible_preferred_nodes()[:self.max_peers]
        for node in preferred_nodes:
            self._preferred_node_tracker[node] = time.time()
            yield node

        num_nodes_needed = max(0, self.max_peers - len(preferred_nodes))
        yield from self.discovery.get_random_nodes(num_nodes_needed)


class ChainInfo:
    def __init__(self, node_type, node_wallet_address, chain_head_root_hashes):
        self.node_type=node_type
        self.node_wallet_address=node_wallet_address
        self.chain_head_root_hashes = chain_head_root_hashes


PEER_MSG_TYPE = Tuple[BasePeer, protocol.Command, protocol._DecodedMsgType]


def _test():
    """
    Create a Peer instance connected to a local geth instance and log messages exchanged with it.

    Use the following command line to run geth:

        ./build/bin/geth -vmodule p2p=4,p2p/discv5=0,eth/*=0 \
          -nodekeyhex 45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8 \
          -testnet -lightserv 90
    """
    import argparse
    import signal
    from evm.chains.ropsten import RopstenChain, ROPSTEN_GENESIS_HEADER
    from evm.db.backends.memory import MemoryDB
    from tests.p2p.integration_test_helpers import FakeAsyncHeaderDB, LocalGethPeerPool
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

    parser = argparse.ArgumentParser()
    parser.add_argument('-light', action='store_true', help="Connect as a light node")
    args = parser.parse_args()

    peer_class = ETHPeer  # type: ignore
    if args.light:
        peer_class = LESPeer  # type: ignore
    headerdb = FakeAsyncHeaderDB(MemoryDB())
    headerdb.persist_header(ROPSTEN_GENESIS_HEADER)
    network_id = RopstenChain.network_id
    loop = asyncio.get_event_loop()
    peer_pool = LocalGethPeerPool(peer_class, headerdb, network_id, ecies.generate_privkey())

    async def request_stuff():
        # Request some stuff from ropsten's block 2440319
        # (https://ropsten.etherscan.io/block/2440319), just as a basic test.
        nonlocal peer_pool
        while not peer_pool.peers:
            peer_pool.logger.info("Waiting for peer connection...")
            await asyncio.sleep(0.2)
        peer = peer_pool.peers[0]
        block_hash = decode_hex(
            '0x59af08ab31822c992bb3dad92ddb68d820aa4c69e9560f07081fa53f1009b152')
        if peer_class == ETHPeer:
            peer = cast(ETHPeer, peer)
            peer.sub_proto.send_get_block_headers(block_hash, 1)
            peer.sub_proto.send_get_block_bodies([block_hash])
            peer.sub_proto.send_get_receipts([block_hash])
        else:
            peer = cast(LESPeer, peer)
            request_id = 1
            peer.sub_proto.send_get_block_headers(block_hash, 1, request_id)
            peer.sub_proto.send_get_block_bodies([block_hash], request_id + 1)
            peer.sub_proto.send_get_receipts(block_hash, request_id + 2)

    sigint_received = asyncio.Event()
    for sig in [signal.SIGINT, signal.SIGTERM]:
        loop.add_signal_handler(sig, sigint_received.set)

    async def exit_on_sigint():
        await sigint_received.wait()
        await peer_pool.cancel()
        loop.stop()

    asyncio.ensure_future(exit_on_sigint())
    asyncio.ensure_future(request_stuff())
    asyncio.ensure_future(peer_pool.run())
    loop.set_debug(True)
    loop.run_forever()
    loop.close()


if __name__ == "__main__":
    _test()