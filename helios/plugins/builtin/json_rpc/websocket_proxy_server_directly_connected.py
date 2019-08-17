import asyncio
import websockets
import sys
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



from helios.rpc.proxy import BaseProxy

# Instead of piping requests through the IPC socket, we are connecting directly with the code. This allows
# async requests.
class Proxy(BaseProxy):

    def __init__(self, websocket_url, rpc_execute):
        self.websocket_url = websocket_url

        url = urlparse(websocket_url)
        assert url.scheme == 'ws'
        self.hostname, self.port = url.hostname, url.port

        self.keepalive_timeout = 30

        self.server = None

        self.rpc_execute = rpc_execute


    async def process(self, raw_request):
        # Connect directly to rpc
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




