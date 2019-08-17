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

import aiohttp

try:
    from json import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

from aiohttp import web

from helios.rpc.proxy import BaseProxy
import json

class Proxy(BaseProxy):

    def __init__(self, http_url, rpc_execute):
        self.http_url = http_url

        url = urlparse(http_url)
        assert url.scheme == 'http'
        self.hostname, self.port = url.hostname, url.port

        self.keepalive_timeout = 30

        self.rpc_execute = rpc_execute

    async def process(self, raw_request):
        # Connect directly to rpc
        request = json.loads(raw_request)
        return await self.rpc_execute(request)

    async def handle_post(self, request):
        text = await request.text()
        print("HTTP request: {}".format(text))
        response = await self.process(text)
        print("HTTP response: {}".format(response))
        return web.Response(text=response, content_type='application/json')

    async def handle_get(self, request):
        return web.Response(text="Helios Protocol JSON RPC HTTP REST proxy online. Use POST to call RPC methods | {}:{}".format(self.hostname, self.port))

    def run(self):
        app = web.Application()
        app.router.add_get('/', self.handle_get)
        app.router.add_post('/', self.handle_post)
        web.run_app(app, host=self.hostname, port=self.port)



if __name__ == '__main__':
    print('starting')
    backend_path = '/home/tommy/.local/share/helios/mainnet/jsonrpc.ipc'
    websocket_url = 'http://0.0.0.0:30304'
    proxy = Proxy(websocket_url, backend_path)
    proxy.run()
    print('finished')


