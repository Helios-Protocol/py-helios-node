from typing import (
    Any
)
from eth_utils import (
    encode_hex,
)

from hvm.chains.base import (
    Chain
)
from hvm.tools.fixtures import (
    apply_fixture_block_to_chain,
    new_chain_from_fixture,
    normalize_block,
    normalize_blockchain_fixtures,
)

from helios.rpc.format import (
    format_params,
)
from helios.rpc.modules import (
    RPCModule,
)


class EVM(RPCModule):
    @format_params(normalize_blockchain_fixtures)
    async def resetToGenesisFixture(self, chain_info: Any) -> Chain:
        '''
        This method is a special case. It returns a new chain object
        which is then replaced inside :class:`~helios.rpc.main.RPCServer`
        for all future calls.
        '''
        return new_chain_from_fixture(chain_info, type(self._chain))

    @format_params(normalize_block)
    async def applyBlockFixture(self, block_info: Any) -> str:
        '''
        This method is a special case. It returns a new chain object
        which is then replaced inside :class:`~helios.rpc.main.RPCServer`
        for all future calls.
        '''
        _, _, rlp_encoded = apply_fixture_block_to_chain(block_info, self._chain)
        return encode_hex(rlp_encoded)
