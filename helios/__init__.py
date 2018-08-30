import pkg_resources

# TODO: update this to use the `helios` version once extracted from py-hvm
try:
    __version__: str = pkg_resources.get_distribution("helios").version
except pkg_resources.DistributionNotFound:
    # mypy doesn't like that `__version__` is defined twice
    __version__: str = pkg_resources.get_distribution("py-helios-node").version  # type: ignore

#from .main import (  # noqa: F401
#    main,
#)

#
#  Ensure we can reach 1024 frames of recursion
#
#sys.setrecursionlimit(1024 * 10)
