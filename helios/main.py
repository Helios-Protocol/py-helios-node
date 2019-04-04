from argparse import ArgumentParser, Namespace
import getpass
import os
import sys
import asyncio
import logging
import signal
from typing import (
    Any,
    Dict,
    Type,
    List,
)

from cancel_token import CancelToken
from lahja import (
    EventBus,
    Endpoint,
)

from hvm.chains.mainnet import (
    MAINNET_NETWORK_ID,
)
from hvm.db.backends.base import BaseDB
from hvm.db.backends.level import LevelDB

from hvm.db.journal import (
    JournalDB,
)

from hp2p.service import BaseService

from helios.exceptions import (
    AmbigiousFileSystem,
    MissingPath,
)
from helios.chains import (
    initialize_data_dir,
    is_data_dir_initialized,
    get_chaindb_manager,
    get_chain_manager)
from helios.cli_parser import (
    parser,
    subparser,
)
from helios.config import (
    ChainConfig,
)
from helios.constants import (
    MAIN_EVENTBUS_ENDPOINT,
    NETWORKING_EVENTBUS_ENDPOINT,
)
from helios.events import (
    ShutdownRequest
)
from helios.extensibility import (
    BaseManagerProcessScope,
    MainAndIsolatedProcessScope,
    PluginManager,
    SharedProcessScope,
)
from helios.extensibility.events import (
    HeliosStartupEvent
)
from helios.plugins.registry import (
    ENABLED_PLUGINS
)
from helios.utils.ipc import (
    wait_for_ipc,
    kill_process_gracefully,
)
from helios.utils.logging import (
    enable_warnings_by_default,
    setup_log_levels,
    setup_helios_stderr_logging,
    setup_helios_file_and_queue_logging,
    with_queued_logging,
)
from helios.utils.mp import (
    ctx,
)
from helios.utils.profiling import (
    setup_cprofiler,
    sync_periodically_report_memory_stats)
from helios.utils.shutdown import (
    exit_signal_with_service,
)
from helios.utils.version import (
    construct_helios_client_identifier,
    is_prerelease,
)
from hvm.tools.logging import TRACE_LEVEL_NUM
from helios.utils.db_proxy import create_db_manager

PRECONFIGURED_NETWORKS = {MAINNET_NETWORK_ID}

HELIOS_HEADER = (
    "\n"    
    " __  __     ______     __         __     ______     ______    \n"
    r"/\ \_\ \   /\  ___\   /\ \       /\ \   /\  __ \   /\  ___\ " + "\n"
    r"\ \  __ \  \ \  __\   \ \ \____  \ \ \  \ \ \/\ \  \ \___  \ " + "\n"
    r" \ \_\ \_\  \ \_____\  \ \_____\  \ \_\  \ \_____\  \/\_____\ " + "\n"
    r"  \/_/\/_/   \/_____/   \/_____/   \/_/   \/_____/   \/_____/ " + "\n"
)

HELIOS_AMBIGIOUS_FILESYSTEM_INFO = (
    "Could not initialize data directory\n\n"
    "   One of these conditions must be met:\n"
    "   * HOME environment variable set\n"
    "   * XDG_HELIOS_ROOT environment variable set\n"
    "   * HELIOS_DATA_DIR environment variable set\n"
    "   * --data-dir command line argument is passed\n"
    "\n"
    "   In case the data directory is outside of the helios root directory\n"
    "   Make sure all paths are pre-initialized as Helios won'setup_helios_stderr_loggingt attempt\n"
    "   to create directories outside of the helios root directory\n"
)


def main() -> None:

    event_bus = EventBus(ctx)
    main_endpoint = event_bus.create_endpoint(MAIN_EVENTBUS_ENDPOINT)
    main_endpoint.connect()

    plugin_manager = setup_plugins(
        MainAndIsolatedProcessScope(event_bus, main_endpoint)
    )
    plugin_manager.amend_argparser_config(parser, subparser)
    args = parser.parse_args()

    #
    # Dev testing stuff
    #
    if args.start_memory_profile:
        os.environ["PYTHONTRACEMALLOC"] = '1'
    if args.rand_db:
        os.environ["GENERATE_RANDOM_DATABASE"] = 'true'
    if args.instance is not None:

        from helios.utils.xdg import get_xdg_helios_root
        args.port = args.port + args.instance * 2

        if args.instance != 0:
            args.do_rpc_http_server = False
        subdir = 'instance_' + str(args.instance)
        absolute_path = get_xdg_helios_root() / subdir

        absolute_dir = os.path.dirname(os.path.realpath(__file__))
        absolute_keystore_path = absolute_dir + '/keystore/'
        args.keystore_path = absolute_keystore_path + subdir

        args.keystore_password = 'dev'

        os.environ["HELIOS_DATA_DIR"] = str(absolute_path.resolve())
        os.environ["INSTANCE_NUMBER"] = str(args.instance)


    #
    #
    #
    if not args.keystore_password and not hasattr(args, 'func'):
        password = getpass.getpass(prompt='Keystore Password: ')
        args.keystore_password = password



    if args.network_id not in PRECONFIGURED_NETWORKS:
        raise NotImplementedError(
            "Unsupported network id: {0}.  Only the ropsten and mainnet "
            "networks are supported.".format(args.network_id)
        )

    has_ambigous_logging_config = (
        args.log_levels is not None and
        None in args.log_levels and
        args.stderr_log_level is not None
    )


    if has_ambigous_logging_config:
        parser.error(
            "\n"
            "Ambiguous logging configuration: The logging level for stderr was "
            "configured with both `--stderr-log-level` and `--log-level`. "
            "Please remove one of these flags",
        )

    if is_prerelease():
        # this modifies the asyncio logger, but will be overridden by any custom settings below
        enable_warnings_by_default(False)

    stderr_logger, formatter, handler_stream = setup_helios_stderr_logging(
        args.stderr_log_level or (args.log_levels and args.log_levels.get(None))
    )


    log_levels = {}
    if args.log_levels and args.log_levels.get(None) == TRACE_LEVEL_NUM:
        print("SETTING TRACE LOG LEVELS")
        log_levels['default'] = TRACE_LEVEL_NUM
        log_levels['hvm'] = TRACE_LEVEL_NUM
        log_levels['hp2p'] = TRACE_LEVEL_NUM
        log_levels['helios'] = TRACE_LEVEL_NUM

        log_levels['urllib3'] = TRACE_LEVEL_NUM
        log_levels['ssdp'] = TRACE_LEVEL_NUM
        log_levels['Service'] = TRACE_LEVEL_NUM

        log_levels['Action'] = TRACE_LEVEL_NUM
        log_levels['Device'] = TRACE_LEVEL_NUM
        log_levels['helios.extensibility'] = TRACE_LEVEL_NUM

    else:
        log_levels['default'] = logging.INFO

        log_levels['urllib3'] = logging.INFO
        log_levels['ssdp'] = logging.INFO
        log_levels['Service'] = logging.INFO

        log_levels['hvm'] = logging.DEBUG  #sets all of hvm
        log_levels['hvm.db.account.AccountDB'] = logging.DEBUG
        log_levels['hvm.vm.base.VM.VM'] = logging.DEBUG
        log_levels['hvm.chain'] = logging.DEBUG
        #log_levels['hvm.chain.chain.Chain'] = logging.DEBUG
        log_levels['hvm.db.chain_head.ChainHeadDB'] = logging.DEBUG
        log_levels['hvm.db.chain_db.ChainDB'] = logging.DEBUG
        log_levels['hvm.db.consensus'] = logging.DEBUG
        log_levels['hvm.memoryLogger'] = logging.DEBUG

        #log_levels['hp2p'] = logging.INFO


        log_levels['hp2p.peer'] = logging.DEBUG
        log_levels['hp2p.peer.PeerPool'] = logging.DEBUG
        log_levels['hp2p.consensus.Consensus'] = logging.DEBUG
        log_levels['hp2p.SmartContractChainManager'] = logging.DEBUG
        log_levels['hp2p.kademlia.KademliaProtocol'] = logging.DEBUG
        log_levels['hp2p.discovery.DiscoveryProtocol'] = logging.INFO
        log_levels['hp2p.discovery.DiscoveryService'] = logging.INFO
        log_levels['hp2p.nat.UPnPService'] = logging.CRITICAL
        log_levels['connectionpool'] = logging.CRITICAL
        log_levels['hp2p.protocol'] = logging.DEBUG
        log_levels['hp2p.protocol.Protocol'] = logging.DEBUG


        #log_levels['helios'] = logging.INFO
        log_levels['helios.rpc.ipc'] = logging.INFO
        log_levels['helios.Node'] = logging.INFO
        log_levels['helios.sync'] = logging.DEBUG
        log_levels['helios.protocol'] = logging.INFO
        log_levels['helios.protocol.common'] = logging.DEBUG
        log_levels['helios.protocol.hls.peer.HLSPeer'] = 5
        log_levels['helios.memoryLogger'] = logging.DEBUG

        log_levels['hp2p.hls'] = logging.INFO
        log_levels['helios.server.FullServer'] = logging.DEBUG

        log_levels['Action'] = logging.INFO
        log_levels['Device'] = logging.INFO
        log_levels['helios.extensibility'] = logging.INFO


        setup_log_levels(log_levels = log_levels)





    try:
        chain_config = ChainConfig.from_parser_args(args)
    except AmbigiousFileSystem:
        parser.error(HELIOS_AMBIGIOUS_FILESYSTEM_INFO)

    if not is_data_dir_initialized(chain_config):
        # TODO: this will only work as is for chains with known genesis
        # parameters.  Need to flesh out how genesis parameters for custom
        # chains are defined and passed around.
        try:
            initialize_data_dir(chain_config)
        except AmbigiousFileSystem:
            parser.error(HELIOS_AMBIGIOUS_FILESYSTEM_INFO)
        except MissingPath as e:
            parser.error(
                "\n"
                f"It appears that {e.path} does not exist. "
                "Helios does not attempt to create directories outside of its root path. "
                "Either manually create the path or ensure you are using a data directory "
                "inside the XDG_HELIOS_ROOT path"
            )

    file_logger, log_queue, listener = setup_helios_file_and_queue_logging(
        stderr_logger,
        formatter,
        handler_stream,
        chain_config,
        args.file_log_level,
    )

    display_launch_logs(chain_config)

    # compute the minimum configured log level across all configured loggers.
    min_configured_log_level = min(
        stderr_logger.level,
        file_logger.level,
        *(args.log_levels or {}).values(),
        *(log_levels or {}).values()
    )


    extra_kwargs = {
        'log_queue': log_queue,
        'log_level': min_configured_log_level,
        'log_levels': log_levels,
        'profile': args.profile,
    }

    # Plugins can provide a subcommand with a `func` which does then control
    # the entire process from here.
    if hasattr(args, 'func'):
        args.func(args, chain_config)
    else:
        helios_boot(
            args,
            chain_config,
            extra_kwargs,
            plugin_manager,
            listener,
            event_bus,
            main_endpoint,
            stderr_logger,
        )


def helios_boot(args: Namespace,
                chain_config: ChainConfig,
                extra_kwargs: Dict[str, Any],
                plugin_manager: PluginManager,
                listener: logging.handlers.QueueListener,
                event_bus: EventBus,
                main_endpoint: Endpoint,
                logger: logging.Logger) -> None:
    # start the listener thread to handle logs produced by other processes in
    # the local logger.
    listener.start()

    networking_endpoint = event_bus.create_endpoint(NETWORKING_EVENTBUS_ENDPOINT)
    event_bus.start()

    # First initialize the database process.
    database_server_process = ctx.Process(
        target=run_database_process,
        args=(
            chain_config,
            LevelDB,
        ),
        kwargs=extra_kwargs,
    )

    chain_processes = []
    for i in range(chain_config.num_chain_processes):
        chain_process = ctx.Process(
            target=run_chain_process,
            args=(
                chain_config,
                i
            ),
            kwargs=extra_kwargs,
        )
        chain_processes.append(chain_process)


    networking_process = ctx.Process(
        target=launch_node,
        args=(args, chain_config, networking_endpoint,),
        kwargs=extra_kwargs,
    )

    # start the processes
    database_server_process.start()
    logger.info("Started DB server process (pid=%d)", database_server_process.pid)

    # networking process needs the IPC socket file provided by the database process
    try:
        wait_for_ipc(chain_config.database_ipc_path)
    except TimeoutError as e:
        logger.error("Timeout waiting for database to start.  Exiting...")
        kill_process_gracefully(database_server_process, logger)
        ArgumentParser().error(message="Timed out waiting for database start")


    for i in range(chain_config.num_chain_processes):
        chain_process = chain_processes[i]
        chain_process.start()
        logger.info("Started chain instance {} process (pid={})".format(i,database_server_process.pid))
        try:
            wait_for_ipc(chain_config.get_chain_ipc_path(i))
        except TimeoutError as e:
            logger.error("Timeout waiting for chain instance {} to start.  Exiting...".format(i))
            kill_process_gracefully(database_server_process, logger)
            for j in range(i+1):
                kill_process_gracefully(chain_processes[j], logger)
            ArgumentParser().error(message="Timed out waiting for chain instance {} start".format(i))


    networking_process.start()
    logger.info("Started networking process (pid=%d)", networking_process.pid)

    main_endpoint.subscribe(
        ShutdownRequest,
        lambda ev: kill_helios_gracefully(
            logger,
            database_server_process,
            chain_processes,
            networking_process,
            plugin_manager,
            main_endpoint,
            event_bus
        )
    )

    plugin_manager.prepare(args, chain_config, extra_kwargs)
    plugin_manager.broadcast(HeliosStartupEvent(
        args,
        chain_config
    ))
    try:
        loop = asyncio.get_event_loop()
        loop.run_forever()
        loop.close()
    except KeyboardInterrupt:
        kill_helios_gracefully(
            logger,
            database_server_process,
            chain_processes,
            networking_process,
            plugin_manager,
            main_endpoint,
            event_bus
        )


def kill_helios_gracefully(logger: logging.Logger,
                           database_server_process: Any,
                           chain_processes: List[Any],
                           networking_process: Any,
                           plugin_manager: PluginManager,
                           main_endpoint: Endpoint,
                           event_bus: EventBus,
                           message: str="Helios shudown complete\n") -> None:
    # When a user hits Ctrl+C in the terminal, the SIGINT is sent to all processes in the
    # foreground *process group*, so both our networking and database processes will terminate
    # at the same time and not sequentially as we'd like. That shouldn't be a problem but if
    # we keep getting unhandled BrokenPipeErrors/ConnectionResetErrors like reported in
    # https://github.com/ethereum/py-evm/issues/827, we might want to change the networking
    # process' signal handler to wait until the DB process has terminated before doing its
    # thing.
    # Notice that we still need the kill_process_gracefully() calls here, for when the user
    # simply uses 'kill' to send a signal to the main process, but also because they will
    # perform a non-gracefull shutdown if the process takes too long to terminate.
    logger.info('Keyboard Interrupt: Stopping')
    plugin_manager.shutdown_blocking()
    main_endpoint.stop()
    event_bus.stop()
    for name, process in [("DB", database_server_process), ("Networking", networking_process), *[("Chain", chain_process) for chain_process in chain_processes]]:
        # Our sub-processes will have received a SIGINT already (see comment above), so here we
        # wait 2s for them to finish cleanly, and if they fail we kill them for real.
        if process is not None:
            process.join(2)
            if process.is_alive():
                kill_process_gracefully(process, logger)
            logger.info('%s process (pid=%d) terminated', name, process.pid)


    # This is required to be within the `kill_helios_gracefully` so that
    # plugins can trigger a shutdown of the helios process.
    ArgumentParser().exit(message=message)


@setup_cprofiler('run_database_process')
@with_queued_logging
def run_database_process(chain_config: ChainConfig, db_class: Type[BaseDB]) -> None:
    with chain_config.process_id_file('database'):

        if chain_config.report_memory_usage:
            from threading import Thread
            memory_logger = logging.getLogger('hvm.memoryLogger')

            t = Thread(target=sync_periodically_report_memory_stats, args=(chain_config.memory_usage_report_interval, memory_logger))
            t.start()


        base_db = db_class(db_path=chain_config.database_dir)

        # TODO:remove
        base_db = JournalDB(base_db)

        manager = get_chaindb_manager(chain_config, base_db)
        server = manager.get_server()  # type: ignore

        def _sigint_handler(*args: Any) -> None:
            server.stop_event.set()

        signal.signal(signal.SIGINT, _sigint_handler)
        try:
            server.serve_forever()
        except SystemExit:
            server.stop_event.set()
            raise


@setup_cprofiler('run_chain_process')
@with_queued_logging
def run_chain_process(chain_config: ChainConfig, instance = 0) -> None:
    with chain_config.process_id_file('database_{}'.format(instance)):
        # connect with database process
        db_manager = create_db_manager(chain_config.database_ipc_path)
        db_manager.connect()

        base_db = db_manager.get_db()

        # start chain process
        manager = get_chain_manager(chain_config, base_db, instance)
        server = manager.get_server()  # type: ignore

        def _sigint_handler(*args: Any) -> None:
            server.stop_event.set()

        signal.signal(signal.SIGINT, _sigint_handler)
        try:
            server.serve_forever()
        except SystemExit:
            server.stop_event.set()
            raise



@setup_cprofiler('launch_node')
@with_queued_logging
def launch_node(args: Namespace, chain_config: ChainConfig, endpoint: Endpoint) -> None:
    with chain_config.process_id_file('networking'):

        endpoint.connect()

        NodeClass = chain_config.node_class
        # Temporary hack: We setup a second instance of the PluginManager.
        # The first instance was only to configure the ArgumentParser whereas
        # for now, the second instance that lives inside the networking process
        # performs the bulk of the work. In the future, the PluginManager
        # should probably live in its own process and manage whether plugins
        # run in the shared plugin process or spawn their own.

        plugin_manager = setup_plugins(SharedProcessScope(endpoint))
        plugin_manager.prepare(args, chain_config)
        plugin_manager.broadcast(HeliosStartupEvent(
            args,
            chain_config
        ))

        node = NodeClass(plugin_manager, chain_config)
        loop = node.get_event_loop()
        asyncio.ensure_future(handle_networking_exit(node, plugin_manager, endpoint), loop=loop)
        asyncio.ensure_future(node.run(), loop=loop)
        loop.run_forever()
        loop.close()


def display_launch_logs(chain_config: ChainConfig) -> None:
    logger = logging.getLogger('helios')
    logger.info(HELIOS_HEADER)
    logger.info(construct_helios_client_identifier())
    logger.info("Helios DEBUG log file is created at %s", str(chain_config.logfile_path))


async def handle_networking_exit(service: BaseService,
                                 plugin_manager: PluginManager,
                                 endpoint: Endpoint) -> None:

    async with exit_signal_with_service(service):
        await plugin_manager.shutdown()
        endpoint.stop()


def setup_plugins(scope: BaseManagerProcessScope) -> PluginManager:
    plugin_manager = PluginManager(scope)
    # TODO: Implement auto-discovery of plugins based on some convention/configuration scheme
    plugin_manager.register(ENABLED_PLUGINS)

    return plugin_manager


if __name__ == "__main__":
    __spec__ = 'None'
    main()