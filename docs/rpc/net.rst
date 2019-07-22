=================================
net JSON RPC Documentation
=================================


This is the documentation for our main RPC module called net.
At this point, our net module is identical to that of Ethereum. You can find documentation for it here: https://github.com/ethereum/wiki/wiki/JSON-RPC



RPC Functions
-------------

All RPC calls must also include parameters jsonrpc and id. jsonrpc is the version of the rpc, which is currently "2.0", and id should be a unique number for each call you make.

Example:
::

    {"jsonrpc": "2.0", "method": "net_version", "params": [], "id":1337}

net_version
~~~~~~~~~~~

Returns the network id of the node.
https://github.com/ethereum/wiki/wiki/JSON-RPC#net_version


net_peerCount
~~~~~~~~~~~~~

Returns the number of peers currently connected to this node.
https://github.com/ethereum/wiki/wiki/JSON-RPC#net_peerCount


net_listening
~~~~~~~~~~~~~

Returns `True` if the client is actively listening for network connections
https://github.com/ethereum/wiki/wiki/JSON-RPC#net_listening
