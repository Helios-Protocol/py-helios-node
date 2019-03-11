from argparse import (
    ArgumentParser,
    _SubParsersAction,
)

from helios.extensibility import (
    BaseIsolatedPlugin,
)

from .websocket_proxy_server import Proxy as rpc_websocket_proxy


class RpcWebsocketProxyPlugin(BaseIsolatedPlugin):

    @property
    def name(self) -> str:
        return "RPC Websocket Proxy"

    def should_start(self) -> bool:
        return (not self.context.args.disable_rpc_websocket_proxy) and self.context.chain_config.is_main_instance

    def configure_parser(self, arg_parser: ArgumentParser, subparser: _SubParsersAction) -> None:
        arg_parser.add_argument(
            '--disable_rpc_websocket_proxy',
            action="store_true",
            help="Should we disable the RPC websocket proxy server?",
        )


    def start(self) -> None:
        self.logger.info('RPC Websocket proxy started')
        self.context.event_bus.connect()

        proxy_url = "ws://0.0.0.0:" + str(self.context.chain_config.rpc_port)
        rpc_websocket_proxy_service = rpc_websocket_proxy(proxy_url, self.context.chain_config.jsonrpc_ipc_path)
        rpc_websocket_proxy_service.run()



