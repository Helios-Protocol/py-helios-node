import pkg_resources
import sys

# TODO: update this to use the `helios` version once extracted from py-evm
__version__: str
try:
    __version__ = pkg_resources.get_distribution("helios").version
except pkg_resources.DistributionNotFound:
    __version__ = "hls-{0}".format(
        pkg_resources.get_distribution("py-helios-node").version,
    )

# This is to ensure we call setup_trace_logging() before anything else.
import hvm as _eth_module  # noqa: F401

if sys.platform in {'darwin', 'linux'}:
    # Set `uvloop` as the default event loop
    import asyncio  # noqa: E402
    import uvloop  # noqa: E402
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

from .main import (  # noqa: F401
    main,
)
