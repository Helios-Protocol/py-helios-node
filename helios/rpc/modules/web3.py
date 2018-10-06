from eth_hash.auto import keccak
from eth_utils import decode_hex, encode_hex

from helios.utils.version import construct_helios_client_identifier

from helios.rpc.modules import (
    RPCModule,
)


class Web3(RPCModule):
    async def clientVersion(self) -> str:
        """
        Returns the current client version.
        """
        return construct_helios_client_identifier()

    async def sha3(self, data: str) -> str:
        """
        Returns Keccak-256 of the given data.
        """
        return encode_hex(keccak(decode_hex(data)))
