from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from helios.nodes.base import Node
    from hvm.chains.base import BaseChain

class RPCModule:
    _chain: 'BaseChain' = None
    _node: 'Node' = None

    def __init__(self, node: 'Node', chain=None, p2p_server=None):
        self._chain = chain
        self._p2p_server = p2p_server
        self._node = node

    def set_chain(self, chain):
        self._chain = chain

    