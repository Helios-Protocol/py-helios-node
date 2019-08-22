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
from aiohttp.web import  GracefulExit

from helios.rpc.proxy import BaseProxy
import json



class Proxy(BaseProxy):

    def __init__(self, http_url, rpc_execute, use_async = True):
        self.http_url = http_url
        self.use_async = use_async

        url = urlparse(http_url)
        assert url.scheme == 'http'
        self.hostname, self.port = url.hostname, url.port

        self.keepalive_timeout = 30

        self.rpc_execute = rpc_execute

        self.sync_lock = asyncio.Lock()

    async def process(self, raw_request):
        request = json.loads(raw_request)

        if self.use_async:
            return await self.rpc_execute(request)
        else:
            async with self.sync_lock:
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
        try:
            web.run_app(app, host=self.hostname, port=self.port, handle_signals=True, print=False)
        except Exception:
            pass
        finally:
            print("Shutting down http proxy")
            raise GracefulExit()
        #web.run_app(app, host=self.hostname, port=self.port)



if __name__ == '__main__':
    print('starting')
    backend_path = '/home/tommy/.local/share/helios/mainnet/jsonrpc.ipc'
    websocket_url = 'http://0.0.0.0:30304'
    proxy = Proxy(websocket_url, backend_path)
    proxy.run()
    print('finished')


