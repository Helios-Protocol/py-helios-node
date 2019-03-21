import secrets
import time
import asyncio

from typing import (
    Any,
    cast,
    Dict,
    List,
)

from eth_utils import encode_hex


from hp2p.constants import PEER_STAKE_GONE_STALE_TIME_PERIOD
from hvm.exceptions import (
    CanonicalHeadNotFound,
)

from hp2p.exceptions import HandshakeFailure
from hp2p.p2p_proto import DisconnectReason, Disconnect
from hp2p.protocol import (
    Command,
    _DecodedMsgType,
)
from hp2p.utils import (
    extract_wallet_verification_sender,
    create_wallet_verification_signature,
    validate_transaction_signature,
)
from hp2p.kademlia import Node

from helios.protocol.common.peer import (
    BaseChainPeer,
    BaseChainPeerFactory,
    BaseChainPeerPool,
)

from hvm.types import Timestamp

from .commands import (
    Status,
    WalletAddressVerification,
    GetWalletAddressVerification,
)
from .constants import MAX_HEADERS_FETCH
from .proto import HLSProtocol
from .handlers import HLSExchangeHandler

from eth_typing import Address

from helios.protocol.common.datastructures import HashFragmentRequestHistory

class HLSPeer(BaseChainPeer):
    max_headers_fetch = MAX_HEADERS_FETCH

    _supported_sub_protocols = [HLSProtocol]
    sub_proto: HLSProtocol = None

    _requests: HLSExchangeHandler = None

    _last_stake_check_time: Timestamp = 0
    _stake: int = None
    wallet_address = None
    local_salt = None
    peer_salt = None
    chain_head_root_hashes = None
    node_type = None

    hash_fragment_request_history_type_1: HashFragmentRequestHistory = None
    hash_fragment_request_history_type_2: HashFragmentRequestHistory = None

    def get_extra_stats(self) -> List[str]:
        stats_pairs = self.requests.get_stats().items()
        return ['%s: %s' % (cmd_name, stats) for cmd_name, stats in stats_pairs]

    @property
    async def stake(self) -> int:
        if self._last_stake_check_time < (int(time.time()) - PEER_STAKE_GONE_STALE_TIME_PERIOD):
            try:
                self._stake = await self.chaindb.coro_get_mature_stake(Address(self.wallet_address), raise_canonical_head_not_found_error = True)
            except CanonicalHeadNotFound:
                self._stake = None

            self._last_stake_check_time = int(time.time())
        return self._stake

    @property
    def requests(self) -> HLSExchangeHandler:
        if self._requests is None:
            self._requests = HLSExchangeHandler(self)
        return self._requests

    def handle_sub_proto_msg(self, cmd: Command, msg: _DecodedMsgType) -> None:
        if isinstance(cmd, GetWalletAddressVerification):
            msg = cast(Dict[str, Any], msg)
            self.send_wallet_address_verification(msg['primary_salt'])
        else:
            super().handle_sub_proto_msg(cmd, msg)


    async def send_sub_proto_handshake(self) -> None:
        local_salt = secrets.token_bytes(32)
        chain_info = await self._local_chain_info
        self.sub_proto.send_handshake(chain_info, local_salt)
        self.local_salt = local_salt


    async def process_sub_proto_handshake(
            self, cmd: Command, msg: _DecodedMsgType) -> None:
        if not isinstance(cmd, Status):
            await self.disconnect(DisconnectReason.other)
            raise HandshakeFailure(
                "Expected a HLS Status msg, got {}, disconnecting".format(cmd))

        msg = cast(Dict[str, Any], msg)
        if msg['network_id'] != self.network_id:
            await self.disconnect(DisconnectReason.useless_peer)
            raise HandshakeFailure(
                "{} network ({}) does not match ours ({}), disconnecting".format(
                    self, msg['network_id'], self.network_id))

        chain_info = await self._local_chain_info
        genesis_block_hash = chain_info.genesis_block_hash
        if msg['genesis_block_hash'] != genesis_block_hash:
            await self.disconnect(DisconnectReason.useless_peer)
            raise HandshakeFailure(
                "{} genesis ({}) does not match ours ({}), disconnecting".format(
                    self, encode_hex(msg['genesis_block_hash']), encode_hex(genesis_block_hash)))

        self.node_type = msg['node_type']
        self.send_wallet_address_verification(msg['salt'])

        # After the sub_proto handshake, the peer will send back a signed message containing the wallet address
        cmd, msg = await self.read_msg()
        if isinstance(cmd, Disconnect):
            # Peers sometimes send a disconnect msg before they send the sub-proto handshake.
            raise HandshakeFailure(
                "{} disconnected before completing wallet address verification: {}".format(
                    self, msg['reason_name']))
        await self.process_sub_proto_wallet_address_verification(cmd, msg)


    async def process_sub_proto_wallet_address_verification(
            self, cmd: Command, msg: _DecodedMsgType) -> None:
        if not isinstance(cmd, WalletAddressVerification):
            await self.disconnect(DisconnectReason.other)
            raise HandshakeFailure(
                "Expected a HLS WalletAddressVerification msg, got {}, disconnecting".format(cmd))
        msg = cast(Dict[str, Any], msg)

        # make sure the salt they replied with is the salt we sent:
        if msg['salt'] != self.local_salt:
            raise HandshakeFailure("The peer replied with a signed message using the wrong salt")

        validate_transaction_signature(msg['salt'], msg['v'], msg['r'], msg['s'])

        self.wallet_address = extract_wallet_verification_sender(msg['salt'], msg['v'], msg['r'], msg['s'])

    def send_wallet_address_verification(self, salt):
        v, r, s = create_wallet_verification_signature(salt, self.chain_config.node_private_helios_key)
        self.sub_proto.send_wallet_address_verification(salt, v, r, s)
        self.peer_salt = salt
        # self.logger.debug("sending wallet address verification for wallet {}".format(self.chain_config.node_wallet_address))


class HLSPeerFactory(BaseChainPeerFactory):
    peer_class = HLSPeer


class HLSPeerPool(BaseChainPeerPool):
    connected_nodes: Dict[Node, HLSPeer]  # type: ignore
    peer_factory_class = HLSPeerFactory

    @property
    def peers(self, min_stake: int = 0) -> List[HLSPeer]:
        return cast(List[HLSPeer], self.get_peers(min_stake))
