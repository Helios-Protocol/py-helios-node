import argparse

from hvm.chains.mainnet import (
    MAINNET_NETWORK_ID,
)

from hp2p.kademlia import Node

from helios import __version__
from helios.constants import (
    SYNC_FULL,
    SYNC_LIGHT,
)


class ValidateAndStoreEnodes(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values is None:
            return

        enode = Node.from_uri(values)

        if getattr(namespace, self.dest) is None:
            setattr(namespace, self.dest, [])
        enode_list = getattr(namespace, self.dest)
        enode_list.append(enode)


#DEFAULT_LOG_LEVEL = 'info'
DEFAULT_LOG_LEVEL = 'debug'
LOG_LEVEL_CHOICES = (
    'debug',
    'info',
)


parser = argparse.ArgumentParser(description='Trinity')

#
# subparser for sub commands
#
subparser = parser.add_subparsers(dest='subcommand')

#
# Argument Groups
#
trinity_parser = parser.add_argument_group('sync mode')
logging_parser = parser.add_argument_group('logging')
network_parser = parser.add_argument_group('network')
syncing_parser = parser.add_argument_group('sync mode')
chain_parser = parser.add_argument_group('chain')
debug_parser = parser.add_argument_group('debug')


#
# Trinity Globals
#
trinity_parser.add_argument('--version', action='version', version=__version__)
trinity_parser.add_argument(
    '--helios-root-dir',
    help=(
        "The filesystem path to the base directory that helios will store it's "
        "information.  Default: $XDG_DATA_HOME/.local/share/helios"
    ),
)
trinity_parser.add_argument(
    '--port',
    type=int,
    required=False,
    default=30303,
    help=(
        "Port on which helios should listen for incoming hp2p/discovery connections. Default: 30303"
    ),
)

trinity_parser.add_argument(
    '--rpc_port',
    type=int,
    required=False,
    default=30304,
    help=(
        "Port on which helios should listen for incoming RPC JSON connections. Default: 8545"
    ),
)

trinity_parser.add_argument(
    '--do_rpc_http_server',
    type=int,
    required=False,
    default=1,
    help=(
        "Should we run the http RPC server?"
    ),
)


#
# Logging configuration
#
logging_parser.add_argument(
    '-l',
    '--log-level',
    choices=LOG_LEVEL_CHOICES,
    default=DEFAULT_LOG_LEVEL,
    help="Sets the logging level",
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
    '--node_type',
    type=int,
    help=(
        "The node type. #0 is master, 1 is fullnode, 2 is micronode, 4 is network launch node"
    ),
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
    type=int,
    help=(
        "generate a random blockchain database"
    ),
)
    
chain_parser.add_argument(
    '--filter_log',
    default=None,
    help=(
        "Only allow logging for this module"
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
# Add `console` sub-command to helios CLI.
#
console_parser = subparser.add_parser(
    'console', help='run the chain and start the helios REPL')
console_parser.add_argument(
    '--vanilla-shell',
    action='store_true',
    default=False,
    help='start a native Python shell'
)


#
# Add `attach` sub-command to helios CLI.
#
attach_parser = subparser.add_parser(
    'attach',
    help='open an REPL attached to a currently running chain',
)
attach_parser.add_argument(
    '--vanilla-shell',
    action='store_true',
    default=False,
    help='start a native Python shell'
)