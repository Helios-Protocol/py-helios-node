import pkg_resources
import sys

from hvm.utils.logging import (
    setup_trace_logging
)

#
#  Setup TRACE level logging.
#
# This needs to be done before the other imports
setup_trace_logging()

from hvm.chains import (  # noqa: F401
    Chain,
    MainnetChain,
)

#
#  Ensure we can reach 1024 frames of recursion
#
sys.setrecursionlimit(1024 * 10)


__version__ = pkg_resources.get_distribution("py-helios-node").version
