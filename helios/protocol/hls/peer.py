import secrets

from typing import (
    Any,
    cast,
    Dict,
    List,
)


from hvm.exceptions import (
    CanonicalHeadNotFound,
)

from hp2p.exceptions import HandshakeFailure
from hp2p.p2p_proto import DisconnectReason
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


from .commands import (
    Status,
    WalletAddressVerification,
    GetWalletAddressVerification,
)
from .constants import MAX_HEADERS_FETCH
from .proto import HLSProtocol
from .handlers import HLSExchangeHandler


class HLSPeer(BaseChainPeer):
    max_headers_fetch = MAX_HEADERS_FETCH

    _supported_sub_protocols = [HLSProtocol]
    sub_proto: HLSProtocol = None

    _requests: HLSExchangeHandler = None

    stake: int = 0  # testing
    wallet_address = None
    local_salt = None
    peer_salt = None
    chain_head_root_hashes = None
    node_type = None

    def get_extra_stats(self) -> List[str]:
        stats_pairs = self.requests.get_stats().items()
        return ['%s: %s' % (cmd_name, stats) for cmd_name, stats in stats_pairs]

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

    # async def send_sub_proto_handshake(self) -> None:
    #     self.sub_proto.send_handshake(await self._local_chain_info)

    async def send_sub_proto_handshake(self) -> None:
        local_salt = secrets.token_bytes(32)
        chain_info = await self._local_chain_info
        self.sub_proto.send_handshake(chain_info, local_salt)
        self.local_salt = local_salt

    # async def process_sub_proto_handshake(
    #         self, cmd: Command, msg: _DecodedMsgType) -> None:
    #     if not isinstance(cmd, Status):
    #         await self.disconnect(DisconnectReason.subprotocol_error)
    #         raise HandshakeFailure(
    #             "Expected a ETH Status msg, got {}, disconnecting".format(cmd))
    #     msg = cast(Dict[str, Any], msg)
    #     if msg['network_id'] != self.network_id:
    #         await self.disconnect(DisconnectReason.useless_peer)
    #         raise HandshakeFailure(
    #             "{} network ({}) does not match ours ({}), disconnecting".format(
    #                 self, msg['network_id'], self.network_id))
    #     genesis = await self.genesis
    #     if msg['genesis_hash'] != genesis.hash:
    #         await self.disconnect(DisconnectReason.useless_peer)
    #         raise HandshakeFailure(
    #             "{} genesis ({}) does not match ours ({}), disconnecting".format(
    #                 self, encode_hex(msg['genesis_hash']), genesis.hex_hash))
    #     self.head_td = msg['td']
    #     self.head_hash = msg['best_hash']

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
        # genesis = await self.genesis
        # if msg['genesis_hash'] != genesis.hash:
        #     await self.disconnect(DisconnectReason.useless_peer)
        #     raise HandshakeFailure(
        #         "{} genesis ({}) does not match ours ({}), disconnecting".format(
        #             self, encode_hex(msg['genesis_hash']), genesis.hex_hash))
        self.node_type = msg['node_type']
        #self.wallet_address = msg['wallet_address']
        self.chain_head_root_hashes = msg['chain_head_root_hashes']
        self.send_wallet_address_verification(msg['salt'])

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
        try:
            self.stake = await self.chain.coro_get_mature_stake(self.wallet_address)
        except CanonicalHeadNotFound:
            self.stake = 0  # give it the lowest possible stake
        # self.logger.debug("Recieved valid wallet address verification for wallet address {}".format(self.wallet_address))

        # note, when we receive an address verification message, we have to verify that the salt they send back equals local salt

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
    def peers(self) -> List[HLSPeer]:
        return list(self.connected_nodes.values())
