import asyncio
import websockets
import sys
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

#########################
########################
#THIS IS NOT CURRENTLY USED.
########################
#########################

class Proxy(BaseProxy):

    def __init__(self, websocket_url, ipc_path):
        self.websocket_url = websocket_url

        url = urlparse(websocket_url)
        assert url.scheme == 'ws'
        self.hostname, self.port = url.hostname, url.port

        self.keepalive_timeout = 30

        self.server = None

        super().__init__(ipc_path)


    async def interface(self, websocket, path):
        while websocket.open:
            try:
                request = await asyncio.wait_for(websocket.recv(), timeout = self.keepalive_timeout)
            except websockets.exceptions.ConnectionClosed:
                continue
            except asyncio.TimeoutError:
                continue

            print("request: {}".format(request))
            response = self.process(request.encode('utf-8'))
            print("response: {}".format(response))
            await websocket.send(response.decode('utf-8'))

    def run(self):

        if WEBSOCKET_USE_SSL:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(WEBSOCKET_SSL_CERT_FILE_PATH, WEBSOCKET_SSL_KEY_FILE_PATH)

            self.server = websockets.serve(self.interface, self.hostname, self.port, ssl=ssl_context)
            print("JSON-RPC Secure Websocket Proxy: {} -> {}".format(
                self.ipc_path, self.websocket_url), file=sys.stderr, flush=True)
        else:
            self.server = websockets.serve(self.interface, self.hostname, self.port)

            print("JSON-RPC Websocket Proxy: {} -> {}".format(
                self.ipc_path, self.websocket_url), file=sys.stderr, flush=True)

        asyncio.get_event_loop().run_until_complete(self.server)
        asyncio.get_event_loop().run_forever()



if __name__ == '__main__':
    print('starting')
    backend_path = '/home/tommy/.local/share/helios/mainnet/jsonrpc.ipc'
    websocket_url = 'ws://0.0.0.0:30304'
    proxy = Proxy(websocket_url, backend_path)
    proxy.run()
    print('finished')


