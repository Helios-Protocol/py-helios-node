from argparse import (
    ArgumentParser,
    _SubParsersAction,
)

from helios.extensibility import (
    BaseIsolatedPlugin,
)

from helios.plugins.builtin.rpc_http_proxy_through_ipc_socket.http_proxy_server import Proxy as rpc_http_proxy
###
# This one is not used anymore because it is synchronous. There is a new asynchronous one in the json_rpc folder
# This one connects through IPC as well. So it wont be stopped by admin_stopRPC.
###
class RpcHTTPProxyPlugin(BaseIsolatedPlugin):

    @property
    def name(self) -> str:
        return "RPC HTTP Proxy"

    def should_start(self) -> bool:
        return (self.context.args.enable_rpc_http_proxy) and self.context.chain_config.is_main_instance

    def configure_parser(self, arg_parser: ArgumentParser, subparser: _SubParsersAction) -> None:
        arg_parser.add_argument(
            '--enable_rpc_http_proxy-NOT_USED',
            action="store_true",
            help="Should we enable the RPC http proxy?",
        )


    def start(self) -> None:
        self.logger.info('RPC HTTP proxy started')
        self.context.event_bus.connect()

        proxy_url = "http://0.0.0.0:" + str(self.context.chain_config.rpc_port)
        rpc_websocket_proxy_service = rpc_http_proxy(proxy_url, self.context.chain_config.jsonrpc_ipc_path)
        rpc_websocket_proxy_service.run()

