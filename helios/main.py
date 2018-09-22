import asyncio
import logging
import signal
import sys
import os
from typing import Type

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
    serve_chaindb,
)
from helios.console import (
    console,
)
from helios.cli_parser import (
    parser,
)
from helios.config import (
    ChainConfig,
)
from helios.utils.ipc import (
    wait_for_ipc,
    kill_process_gracefully,
)
from helios.utils.logging import (
    setup_trinity_stderr_logging,
    setup_trinity_file_and_queue_logging,
    with_queued_logging,
    setup_log_levels,
)
from helios.utils.mp import (
    ctx,
)
from helios.utils.profiling import (
    setup_cprofiler,
)
from helios.utils.version import (
    construct_trinity_client_identifier,
)

from helios.rpc.http_server import Proxy as http_rpc_proxy


#from helios.dev_tools import load_local_nodes


PRECONFIGURED_NETWORKS = {MAINNET_NETWORK_ID}

HELIOS_HEADER = (
    "\n"    
    " __  __     ______     __         __     ______     ______    \n"
    "/\ \_\ \   /\  ___\   /\ \       /\ \   /\  __ \   /\  ___\   \n"
    "\ \  __ \  \ \  __\   \ \ \____  \ \ \  \ \ \/\ \  \ \___  \  \n"
    " \ \_\ \_\  \ \_____\  \ \_____\  \ \_\  \ \_____\  \/\_____\ \n"
    "  \/_/\/_/   \/_____/   \/_____/   \/_/   \/_____/   \/_____/ \n"
)   

TRINITY_AMBIGIOUS_FILESYSTEM_INFO = (
    "Could not initialize data directory\n\n"
    "   One of these conditions must be met:\n"
    "   * HOME environment variable set\n"
    "   * XDG_TRINITY_ROOT environment variable set\n"
    "   * TRINITY_DATA_DIR environment variable set\n"
    "   * --data-dir command line argument is passed\n"
    "\n"
    "   In case the data directory is outside of the helios root directory\n"
    "   Make sure all paths are pre-initialized as Trinity won't attempt\n"
    "   to create directories outside of the helios root directory\n"
)



#python main.py --instance 1 --filter_log hp2p.chain.ChainSyncer --rand_db 1
def main(instance_number = None) -> None:
    args = parser.parse_args()
    
    log_level = getattr(logging, args.log_level.upper())
    #print('log level = ',log_level)
    stderr_log_level = logging.DEBUG
    file_log_level = logging.DEBUG




    if args.network_id not in PRECONFIGURED_NETWORKS:
        raise NotImplementedError(
            "Unsupported network id: {0}.  Only the ropsten and mainnet "
            "networks are supported.".format(args.network_id)
        )

    #For errors to show, they must pass through stderr_log_level, and the log levels given in setup_log_levels
    stderr_logger, formatter, handler_stream = setup_trinity_stderr_logging(stderr_log_level)

    #print this to see all of the loggers to choose from. have to call it after they are initialized
    #print(logging.Logger.manager.loggerDict)
    log_levels = {}
    log_levels['default'] = logging.INFO


    log_levels['hvm'] = logging.INFO  #sets all of hvm
    log_levels['hvm.db.account.AccountDB'] = logging.INFO
    log_levels['hvm.chain'] = logging.DEBUG
    log_levels['hvm.chain.chain.Chain'] = logging.DEBUG
    log_levels['hvm.db.chain_head.ChainHeadDB'] = logging.INFO
    log_levels['hvm.db.chain_db.ChainDB'] = logging.DEBUG

    log_levels['hp2p'] = logging.INFO
    log_levels['hp2p.chain'] = logging.DEBUG
    log_levels['hp2p.chain.ChainSyncer'] = logging.DEBUG
    log_levels['hp2p.peer'] = logging.INFO
    log_levels['hp2p.peer.PeerPool'] = logging.INFO
    log_levels['hp2p.consensus.Consensus'] = logging.DEBUG
    log_levels['hp2p.kademlia.KademliaProtocol'] = logging.INFO
    log_levels['hp2p.discovery.DiscoveryProtocol'] = logging.INFO
    log_levels['hp2p.discovery.DiscoveryService'] = logging.INFO
    log_levels['hp2p.server.Server'] = logging.DEBUG
    log_levels['hp2p.UPnPService'] = logging.INFO

    log_levels['helios.rpc.ipc'] = logging.DEBUG
    log_levels['helios.Node'] = logging.DEBUG

    log_levels['hp2p.hls'] = logging.INFO





    setup_log_levels(log_levels = log_levels)



    if args.rand_db == 1:
        os.environ["GENERATE_RANDOM_DATABASE"] = 'true'
    if args.instance is not None:
        args.port = args.port + args.instance*2
        if args.instance != 0:
            args.do_rpc_http_server = False
        os.environ["XDG_TRINITY_SUBDIRECTORY"] = 'instance_'+str(args.instance)
        os.environ["INSTANCE_NUMBER"] = str(args.instance)
            
    elif instance_number is not None:
        args.port = args.port + instance_number*2
        if instance_number != 0:
            args.do_rpc_http_server = False
        os.environ["XDG_TRINITY_SUBDIRECTORY"] = 'instance_'+str(instance_number)
        os.environ["INSTANCE_NUMBER"] = str(instance_number)
        
    #args.data_dir = '/d:/Google Drive/forex/blockchain coding/Helios/prototype desktop/py-hvm/helios/data/'


    try:
        chain_config = ChainConfig.from_parser_args(args)
    except AmbigiousFileSystem:
        exit_because_ambigious_filesystem(stderr_logger)
        
        
    if not is_data_dir_initialized(chain_config):
        # TODO: this will only work as is for chains with known genesis
        # parameters.  Need to flesh out how genesis parameters for custom
        # chains are defined and passed around.
        try:
            initialize_data_dir(chain_config)
        except AmbigiousFileSystem:
            exit_because_ambigious_filesystem(stderr_logger)
        except MissingPath as e:
            msg = (
                "\n"
                "It appears that {} does not exist.\n"
                "Trinity does not attempt to create directories outside of its root path\n"
                "Either manually create the path or ensure you are using a data directory\n"
                "inside the XDG_TRINITY_ROOT path"
            ).format(e.path)
            stderr_logger.error(msg)
            sys.exit(1)


    logger, log_queue, listener = setup_trinity_file_and_queue_logging(
        stderr_logger,
        formatter,
        handler_stream,
        chain_config,
        file_log_level,
    )


    min_configured_log_level = min(
        stderr_log_level,
        file_log_level
    )

    
#    print('testtest')
#    for handler in logging.root.handlers:
#        logger.info('test')
#        logger.info(handler)
        
    
    # if console command, run the helios CLI
    if args.subcommand == 'attach':
        console(chain_config.jsonrpc_ipc_path, use_ipython=not args.vanilla_shell)
        sys.exit(0)

    # start the listener thread to handle logs produced by other processes in
    # the local logger.
    listener.start()

    extra_kwargs = {
        'log_queue': log_queue,
        'log_level': min_configured_log_level,
        'log_levels': log_levels,
        'profile': args.profile,
    }

    #base_db = JournalDB(LevelDB)
    #First initialize the database process.
    database_server_process = ctx.Process(
        target=run_database_process,
        args=(
            chain_config,
            LevelDB,
        ),
        kwargs=extra_kwargs,
    )

    networking_process = ctx.Process(
        target=launch_node,
        args=(chain_config, ),
        kwargs=extra_kwargs,
    )





    #start the processes
    database_server_process.start()
    logger.info("Started DB server process (pid=%d)", database_server_process.pid)
    wait_for_ipc(chain_config.database_ipc_path)

    networking_process.start()
    logger.info("Started networking process (pid=%d)", networking_process.pid)

    rpc_http_server_started = False
    if chain_config.do_rpc_http_server and chain_config.jsonrpc_ipc_path:
        rpc_http_proxy_process = ctx.Process(
            target=launch_rpc_http_proxy,
            args=(chain_config,),
        )

        rpc_http_proxy_process.start()
        logger.info("Started RPC HTTP proxy process (pid=%d)", networking_process.pid)
        rpc_http_server_started = True

    try:
        if args.subcommand == 'console':
            console(chain_config.jsonrpc_ipc_path, use_ipython=not args.vanilla_shell)
        else:
            networking_process.join()
    except KeyboardInterrupt:
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
        kill_process_gracefully(database_server_process, logger)
        logger.info('DB server process (pid=%d) terminated', database_server_process.pid)
        kill_process_gracefully(networking_process, logger)
        logger.info('Networking process (pid=%d) terminated', networking_process.pid)

        if rpc_http_server_started:
            kill_process_gracefully(rpc_http_proxy_process, logger)
            logger.info('RPC HTTP proxy process (pid=%d) terminated', networking_process.pid)


@setup_cprofiler('run_database_process')
@with_queued_logging
def run_database_process(chain_config: ChainConfig, db_class: Type[BaseDB]) -> None:
    base_db = db_class(db_path=chain_config.database_dir)
    #TODO:remove
    base_db = JournalDB(base_db)
    #base_db.destroy_db()
    #exit()
    serve_chaindb(chain_config, base_db)


def exit_because_ambigious_filesystem(logger: logging.Logger) -> None:
    logger.error(TRINITY_AMBIGIOUS_FILESYSTEM_INFO)
    sys.exit(1)


async def exit_on_signal(service_to_exit: BaseService) -> None:
    loop = asyncio.get_event_loop()
    sigint_received = asyncio.Event()
    for sig in [signal.SIGINT, signal.SIGTERM]:
        # TODO also support Windows
        loop.add_signal_handler(sig, sigint_received.set)

    await sigint_received.wait()
    try:
        await service_to_exit.cancel()
    finally:
        loop.stop()


@setup_cprofiler('launch_node')
@with_queued_logging
def launch_node(chain_config: ChainConfig) -> None:

    display_launch_logs(chain_config)
    
    NodeClass = chain_config.node_class
    node = NodeClass(chain_config)
    
    run_service_until_quit(node)


def launch_rpc_http_proxy(chain_config: ChainConfig) -> None:

    proxy_url = "http://0.0.0.0:" + str(chain_config.rpc_port)
    http_rpc_proxy_service = http_rpc_proxy(proxy_url, chain_config.jsonrpc_ipc_path)
    http_rpc_proxy_service.run()


def display_launch_logs(chain_config: ChainConfig) -> None:
    logger = logging.getLogger('helios')
    logger.info(HELIOS_HEADER)
    logger.info(construct_trinity_client_identifier())
    


def run_service_until_quit(service: BaseService) -> None:
    loop = asyncio.get_event_loop()
    asyncio.ensure_future(exit_on_signal(service))
    asyncio.ensure_future(service.run())
    loop.run_forever()
    loop.close()



if __name__ == "__main__":
    __spec__ = 'None'
    main(0)
