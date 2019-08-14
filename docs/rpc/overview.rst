=================================
JSON RPC Overview
=================================

The Helios Protocol node software comes with JSON remote procedure call (RPC) functionality. This enables interaction with the node and blockchain through easy to use interfaces including unix sockets, websockets, and HTTP REST. Websockets are enabled by default, but the HTTP REST interface needs to be manually enabled if you would like to use it.


The unix socket interface
-------------------------------------

The unix socket is enabled by default. The default location for the socket is:

::

    ~/.local/share/helios/mainnet/jsonrpc.ipc

If you would like to disable the unix socket, you have to completely disable all RPC functionality. To do this, start the node with the following flags: (Also turning off the websocket proxy)

::

    python main.py --disable-rpc --disable_rpc_websocket_proxy


The websocket interface
-------------------------------------

The websocket interface is enabled by default. So you just need to start the node and it will be running. If you would like to disable the websocket interface, then start the node with the following flags:

::

    python main.py --disable_rpc_websocket_proxy


The HTTP REST interface
-------------------------------------

The HTTP REST interface is disabled by default. Websockets and HTTP REST use the same port, so only one can be enabled at a time. To enable HTTP REST, start the node with the following flags:

::

    python main.py --enable_rpc_http_proxy --disable_rpc_websocket_proxy