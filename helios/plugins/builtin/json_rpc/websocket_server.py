#
# Parts of this code come from cpp-ethereum

# cpp-ethereum is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# cpp-ethereum is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# See <http://www.gnu.org/licenses/> for a copy of the licence.

#!/usr/bin/env python3

"""
JSON-RPC Proxy
This Python script provides HTTP proxy to Unix Socket based JSON-RPC servers.
Check out --help option for more information.
Build with cython:
cython rpcproxy.py --embed
gcc -O3 -I /usr/include/python3.5m -o rpcproxy rpcproxy.c \
-Wl,-Bstatic -lpython3.5m -lz -lexpat -lutil -Wl,-Bdynamic -lpthread -ldl -lm
"""

import asyncio
import threading

import websockets
import errno
import socket
import sys
import time
import json
import ssl

from helios.helios_config import (
    WEBSOCKET_USE_SSL,
    WEBSOCKET_SSL_CERT_FILE_PATH,
    WEBSOCKET_SSL_KEY_FILE_PATH
)

from urllib.parse import urlparse

try:
    from json import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

from eth_utils import (
    to_bytes,
    to_text,
)

from os import path

if sys.platform == 'win32':
    import win32file
    import pywintypes



VERSION = '0.2'
BUFSIZE = 4096
DELIMITER = ord('}')
BACKEND_CONNECTION_TIMEOUT=5
INFO = """JSON-RPC Proxy
Version:  {version}
Proxy:    {proxy_url}
Backend:  {backend_url} (connected: {connected})
"""


class Server:

    def __init__(self, websocket_url, rpc_execute):
        self.websocket_url = websocket_url

        url = urlparse(websocket_url)
        assert url.scheme == 'ws'
        self.hostname, self.port = url.hostname, url.port

        self.keepalive_timeout = 30

        self.server = None

        self.rpc_execute = rpc_execute


    async def process(self, raw_request):
        request = json.loads(raw_request)
        return await self.rpc_execute(request)


    async def interface(self, websocket, path):
        while websocket.open:
            try:
                request = await asyncio.wait_for(websocket.recv(), timeout = self.keepalive_timeout)
            except websockets.exceptions.ConnectionClosed:
                continue
            except asyncio.TimeoutError:
                continue

            print("request: {}".format(request))
            response = await self.process(request)
            print("response: {}".format(response))
            await websocket.send(response)

    def run(self):

        if WEBSOCKET_USE_SSL:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(WEBSOCKET_SSL_CERT_FILE_PATH, WEBSOCKET_SSL_KEY_FILE_PATH)

            self.server = websockets.serve(self.interface, self.hostname, self.port, ssl=ssl_context)
            print("JSON-RPC Secure Websocket Server: {}".format(
                self.websocket_url), file=sys.stderr, flush=True)
        else:
            self.server = websockets.serve(self.interface, self.hostname, self.port)

            print("JSON-RPC Websocket Server: {}".format(
                 self.websocket_url), file=sys.stderr, flush=True)

        return(self.server)
        # asyncio.get_event_loop().run_until_complete(self.server)
        # asyncio.get_event_loop().run_forever()



