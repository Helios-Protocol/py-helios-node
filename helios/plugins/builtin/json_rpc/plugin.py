
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
from helios.utils.verification import save_rpc_admin_password, verify_rpc_admin_password

from .websocket_proxy_server_directly_connected import Proxy as rpc_websocket_server
from .http_proxy_server_directly_connected import Proxy as rpc_http_server

from helios.rpc.main import RPCContext
import sys

from argparse import (
    ArgumentParser,
    Namespace,
    _SubParsersAction,
)
import sys

from helios.config import (
    ChainConfig,
)

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

        arg_parser.add_argument(
            '--enable_rpc_http_proxy',
            action="store_true",
            help="Should we enable the RPC http proxy?",
        )

        arg_parser.add_argument(
            '--enable_private_rpc',
            action="store_true",
            help="This enables the private rpc modules, such as Personal that is used for keystore management and signing.",
        )

        arg_parser.add_argument(
            '--enable_admin_rpc',
            action="store_true",
            help="This enables the admin rpc module.",
        )

        attach_parser = subparser.add_parser(
            'set-admin-rpc-password',
            help='Allows you to set the password used for the admin RPC module',
        )

        attach_parser.set_defaults(func=self.set_admin_rpc_password)

    def set_admin_rpc_password(self,args: Namespace, chain_config: ChainConfig):
        import getpass

        password = getpass.getpass(prompt="Your new admin RPC password")

        file_location = chain_config.rpc_login_config_path

        print(file_location)
        save_rpc_admin_password(password, file_location)

        if not verify_rpc_admin_password(password, file_location):
            raise Exception("A problem occured when verifying the password was saved correctly.")

        print("New password saved successfully")

        sys.exit(1)


    def start(self) -> None:
        self.logger.info('JSON-RPC Server started')
        self.context.event_bus.connect()

        db_manager = create_db_manager(self.context.chain_config.database_ipc_path)
        db_manager.connect()

        chain_class = self.context.chain_config.node_class.chain_class

        db = db_manager.get_db()  # type: ignore
        chain = chain_class(db, wallet_address = self.context.chain_config.node_wallet_address)

        rpc_context = RPCContext(enable_private_modules=self.context.args.enable_private_rpc,
                                 enable_admin_module=self.context.args.enable_admin_rpc,
                                 keystore_dir=self.context.chain_config.keystore_dir,
                                 admin_rpc_password_config_path=self.context.chain_config.rpc_login_config_path)

        rpc = RPCServer(chain, rpc_context, self.context.event_bus, chain_class)
        ipc_server = IPCServer(rpc, self.context.chain_config.jsonrpc_ipc_path)

        loop = asyncio.get_event_loop()
        asyncio.ensure_future(exit_with_service_and_endpoint(ipc_server, self.context.event_bus))
        asyncio.ensure_future(ipc_server.run())

        if self.context.args.enable_rpc_http_proxy and (not self.context.args.disable_rpc_websocket_proxy):
            raise Exception("Cannot run websocket and http proxy at the same time.")

        if (not self.context.args.disable_rpc_websocket_proxy) and self.context.chain_config.is_main_instance:
            self.logger.info('RPC Websocket proxy started')

            proxy_url = "ws://0.0.0.0:" + str(self.context.chain_config.rpc_port)
            rpc_websocket_service = rpc_websocket_server(proxy_url, rpc.execute)

            asyncio.ensure_future(rpc_websocket_service.run())

        elif self.context.args.enable_rpc_http_proxy and self.context.chain_config.is_main_instance:
            self.logger.info('RPC HTTP REST proxy started')

            proxy_url = "http://0.0.0.0:" + str(self.context.chain_config.rpc_port)
            rpc_websocket_service = rpc_http_server(proxy_url, rpc.execute)

            asyncio.ensure_future(rpc_websocket_service.run())

        loop.run_forever()
        loop.close()
