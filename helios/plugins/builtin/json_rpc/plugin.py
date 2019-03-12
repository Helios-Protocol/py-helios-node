from argparse import (
    ArgumentParser,
    _SubParsersAction,
)
import asyncio

from helios.extensibility import (
    BaseIsolatedPlugin,
)

from helios.rpc.main import (
    RPCServer,
)
from helios.rpc.ipc import (
    IPCServer,
)
from helios.utils.db_proxy import (
    create_db_manager
)
from helios.utils.shutdown import (
    exit_with_service_and_endpoint,
)
from .websocket_server import Server as rpc_websocket_server

class JsonRpcServerPlugin(BaseIsolatedPlugin):

    @property
    def name(self) -> str:
        return "JSON-RPC Server"

    def should_start(self) -> bool:
        return not self.context.args.disable_rpc

    def configure_parser(self, arg_parser: ArgumentParser, subparser: _SubParsersAction) -> None:
        arg_parser.add_argument(
            "--disable-rpc",
            action="store_true",
            help="Disables the JSON-RPC Server",
        )
        arg_parser.add_argument(
            '--disable_rpc_websocket_proxy',
            action="store_true",
            help="Should we disable the RPC websocket proxy server?",
        )

    def start(self) -> None:
        self.logger.info('JSON-RPC Server started')
        self.context.event_bus.connect()

        db_manager = create_db_manager(self.context.chain_config.database_ipc_path)
        db_manager.connect()

        chain_class = self.context.chain_config.node_class.chain_class

        db = db_manager.get_db()  # type: ignore
        chain = chain_class(db, wallet_address = self.context.chain_config.node_wallet_address)

        rpc = RPCServer(chain, self.context.event_bus, chain_class)
        ipc_server = IPCServer(rpc, self.context.chain_config.jsonrpc_ipc_path)



        loop = asyncio.get_event_loop()
        asyncio.ensure_future(exit_with_service_and_endpoint(ipc_server, self.context.event_bus))
        asyncio.ensure_future(ipc_server.run())

        if (not self.context.args.disable_rpc_websocket_proxy) and self.context.chain_config.is_main_instance:
            # start websocket proxy
            self.logger.info('RPC Websocket proxy started')

            proxy_url = "ws://0.0.0.0:" + str(self.context.chain_config.rpc_port)
            rpc_websocket_service = rpc_websocket_server(proxy_url, rpc.execute)
            #rpc_websocket_service.run()

            asyncio.ensure_future(rpc_websocket_service.run())

        loop.run_forever()
        loop.close()
