import argparse
import logging
from typing import (
    Any,
)

from hvm.chains.mainnet import (
    MAINNET_NETWORK_ID,
)
from hvm.tools.logging import TRACE_LEVEL_NUM

from hp2p.kademlia import Node

from helios import __version__
from helios.constants import (
    SYNC_FULL,
    SYNC_LIGHT,
)


class ValidateAndStoreEnodes(argparse.Action):
    def __call__(self,
                 parser: argparse.ArgumentParser,
                 namespace: argparse.Namespace,
                 value: Any,
                 option_string: str=None) -> None:
        if value is None:
            return

        enode = Node.from_uri(value)

        if getattr(namespace, self.dest) is None:
            setattr(namespace, self.dest, [])
        enode_list = getattr(namespace, self.dest)
        enode_list.append(enode)


LOG_LEVEL_CHOICES = {
    # numeric versions
    '5': TRACE_LEVEL_NUM,
    '10': logging.DEBUG,
    '20': logging.INFO,
    '30': logging.WARNING,
    '40': logging.ERROR,
    '50': logging.CRITICAL,
    # string versions
    'TRACE': TRACE_LEVEL_NUM,
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARN': logging.WARNING,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL,
}


class ValidateAndStoreLogLevel(argparse.Action):
    def __call__(self,
                 parser: argparse.ArgumentParser,
                 namespace: argparse.Namespace,
                 value: Any,
                 option_string: str=None) -> None:
        if value is None:
            return

        raw_value = value.upper()

        # this is a global log level.
        if raw_value in LOG_LEVEL_CHOICES:
            path = None
            log_level = LOG_LEVEL_CHOICES[raw_value]
        else:
            path, _, raw_log_level = value.partition('=')

            if not path or not raw_log_level:
                raise argparse.ArgumentError(
                    self,
                    "Invalid logging config: '{0}'.  Log level may be specified "
                    "as a global logging level using the syntax `--log-level "
                    "<LEVEL-NAME>` or for to specify the logging level for an "
                    "individual logger, '--log-level "
                    "<LOGGER-NAME>:<LEVEL-NAME>'".format(value)
                )

            try:
                log_level = LOG_LEVEL_CHOICES[raw_log_level.upper()]
            except KeyError:
                raise argparse.ArgumentError(
                    self,
                    (
                        "Invalid logging level.  Got '{0}'.  Must be one of\n"
                        " - 5/10/20/30/40 (numeric logging levels)\n"
                        " - trace/debug/info/warn/warning/error/critical (lowercase)\n"
                        " - TRACE/DEBUG/INFO/WARN/WARNING/ERROR/CRITICAL (uppercase)\n"
                    ).format(raw_log_level),
                )

        if getattr(namespace, self.dest) is None:
            setattr(namespace, self.dest, {})
        log_levels = getattr(namespace, self.dest)
        if path in log_levels:
            if path is None:
                raise argparse.ArgumentError(
                    self,
                    "Global logging has already been configured to '{0}'.  The "
                    "global logging level may only be specified once.".format(
                        log_level,
                    )
                )
            else:
                raise argparse.ArgumentError(
                    self,
                    "The logging level for '{0}' was provided more than once. "
                    "Please ensure the each name is provided only once"
                )
        log_levels[path] = log_level


parser = argparse.ArgumentParser(description='Helios')

#
# subparser for sub commands
#
# Plugins may add subcommands with a `func` attribute
# to gain control over the main Helios process
subparser = parser.add_subparsers(dest='subcommand')

#
# Argument Groups
#
helios_parser = parser.add_argument_group('sync mode')
logging_parser = parser.add_argument_group('logging')
network_parser = parser.add_argument_group('network')
syncing_parser = parser.add_argument_group('sync mode')
chain_parser = parser.add_argument_group('chain')
debug_parser = parser.add_argument_group('debug')


#
# Helios Globals
#
helios_parser.add_argument('--version', action='version', version=__version__)
helios_parser.add_argument(
    '--helios-root-dir',
    help=(
        "The filesystem path to the base directory that helios will store it's "
        "information.  Default: $XDG_DATA_HOME/.local/share/helios"
    ),
)
helios_parser.add_argument(
    '--port',
    type=int,
    required=False,
    default=30303,
    help=(
        "Port on which helios should listen for incoming hp2p/discovery connections. Default: 30303"
    ),
)
helios_parser.add_argument(
    '--rpc_port',
    type=int,
    required=False,
    default=30304,
    help=(
        "Port on which helios should listen for incoming RPC JSON connections. Default: 8545"
    ),
)
#moved this to the plugin
# helios_parser.add_argument(
#     '--do_rpc_http_proxy',
#     type=int,
#     required=False,
#     default=1,
#     help=(
#         "Should we run the RPC http proxy?"
#     ),
# )

#
# Logging configuration
#
logging_parser.add_argument(
    '-l',
    '--log-level',
    action=ValidateAndStoreLogLevel,
    dest="log_levels",
    metavar="LEVEL",
    help=(
        "Configure the logging level. The `LEVEL` may be provide as any of: "
        "TRACE/DEBUG/INFO/WARN/WARNING/ERROR/CRITICAL, "
        "5/10/20/30/40/50, or to specify "
        "the logging level for a specific logger, `--log-level "
        "LOGGER_NAME=LEVEL`.  Default: INFO"
    ),
)
logging_parser.add_argument(
    '--stderr-log-level',
    dest="stderr_log_level",
    help=(
        "Configure the logging level for the stderr logging."
    ),
)
logging_parser.add_argument(
    '--file-log-level',
    dest="file_log_level",
    type=int,
    help=(
        "Configure the logging level for file-based logging."
    ),
)

#
# Main parser for running helios as a node.
#
networkid_parser = network_parser.add_mutually_exclusive_group()
networkid_parser.add_argument(
    '--network-id',
    type=int,
    help="Network identifier (1=Mainnet, 3=Ropsten)",
    default=MAINNET_NETWORK_ID,
)

network_parser.add_argument(
    '--preferred-node',
    action=ValidateAndStoreEnodes,
    dest="preferred_nodes",
    help=(
        "An enode address which will be 'preferred' above nodes found using the "
        "discovery protocol"
    ),
)

network_parser.add_argument(
    '--discv5',
    action='store_true',
    help=("Enable experimental v5 (topic) discovery mechanism"),
)

network_parser.add_argument(
    '--max-peers',
    help=(
        "Maximum number of network peers"
    ),
    type=int,
)


#
# Sync Mode
#
mode_parser = syncing_parser.add_mutually_exclusive_group()
mode_parser.add_argument(
    '--sync-mode',
    choices={SYNC_LIGHT, SYNC_FULL},
    default=SYNC_FULL,
)
mode_parser.add_argument(
    '--light',  # TODO: consider --sync-mode like geth.
    action='store_const',
    const=SYNC_LIGHT,
    dest='sync_mode',
    help="Shortcut for `--sync-mode=light`",
)


#
# Chain configuration
#
chain_parser.add_argument(
    '--data-dir',
    help=(
        "The directory where chain data is stored"
    ),
)
chain_parser.add_argument(
    '--nodekey',
    help=(
        "Hexadecimal encoded private key to use for the nodekey"
    )
)
chain_parser.add_argument(
    '--nodekey-path',
    help=(
        "The filesystem path to the file which contains the nodekey"
    )
)
chain_parser.add_argument(
    '--node_type',
    type=int,
    help=(
        "The node type. #0 is master, 1 is fullnode, 2 is micronode, 4 is network launch node"
    ),
)

chain_parser.add_argument(
    '--network_startup_node',
    action='store_true',
    dest='network_startup_node',
    help="Use this if this is one of the initial nodes at the startup of the network. It will initially assume that this blockchain database has consensus even if there are no other connected nodes.",
)

chain_parser.add_argument(
    '--disable_smart_contract_chain_manager',
    action='store_true',
    dest='disable_smart_contract_chain_manager',
    help="This will stop the node from trying to automatically add new blocks to smart contract chains.",
)

chain_parser.add_argument(
    '--instance',
    type=int,
    help=(
        "The node instance. used when running multiple nodes for local testing"
    ),
)

chain_parser.add_argument(
    '--rand_db',
    action='store_true',
    dest='rand_db',
    help=(
        "generate a random blockchain database"
    ),
)

chain_parser.add_argument(
    '--start_memory_profile',
    action='store_true',
    dest='start_memory_profile',
    help=(
        "Start memory profiler at beginning of program"
    ),
)



chain_parser.add_argument(
    '--keystore_password',
    type=str,
    help=(
        "Password for the keystore containing the private key for this node."
    ),
)

chain_parser.add_argument(
    '--keystore_path',
    type=str,
    help=(
        "Path to the directory containing the keystore file."
    ),
)


#
# Debug configuration
#
debug_parser.add_argument(
    '--profile',
    action='store_true',
    help=(
        "Enables profiling via cProfile."
    ),
)

#
# Add `fix-unclean-shutdown` sub-command to helios CLI
#
fix_unclean_shutdown_parser = subparser.add_parser(
    'fix-unclean-shutdown',
    help='close any dangling processes from a previous unclean shutdown',
)
