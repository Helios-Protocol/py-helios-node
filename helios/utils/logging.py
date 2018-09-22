import functools
import logging
from logging import (
    Logger,
    Formatter,
    StreamHandler
)
from logging.handlers import (
    QueueListener,
    QueueHandler,
    RotatingFileHandler,
)
from multiprocessing import Queue
import os
import sys
from typing import (
    Tuple,
    Callable
)

from cytoolz import dissoc

from helios.config import (
    ChainConfig,
)

from typing import (
    Any,
    cast,
    Dict,
    Tuple,
    TYPE_CHECKING,
    Callable,
)

LOG_BACKUP_COUNT = 10
LOG_MAX_MB = 5

def setup_log_levels(log_levels: Dict[str, int]) -> None:
    try:
        default_level = log_levels['default']
        del(log_levels['default'])
    except KeyError:
        default_level = logging.DEBUG
    #logging.getLogger().setLevel(default_level)

    for name, level in log_levels.items():
        logger = logging.getLogger(name)
        logger.setLevel(level)


def setup_trinity_stderr_logging(level: int=None,
                                 ) -> Tuple[Logger, Formatter, StreamHandler]:
    if level is None:
        level = logging.INFO

    logger = logging.getLogger('helios')
    logger.setLevel(logging.DEBUG)

    handler_stream = logging.StreamHandler(sys.stderr)
    handler_stream.setLevel(level)

    # TODO: allow configuring `detailed` logging
    formatter = logging.Formatter(
        fmt='%(levelname)8s  %(asctime)s  %(module)10s  %(message)s',
        datefmt='%m-%d %H:%M:%S'
    )

    handler_stream.setFormatter(formatter)

    logger.addHandler(handler_stream)

    logger.debug('Logging initialized: PID=%s', os.getpid())

    return logger, formatter, handler_stream


def setup_trinity_file_and_queue_logging(
        logger: Logger,
        formatter: Formatter,
        handler_stream: StreamHandler,
        chain_config: ChainConfig,
        level: int=None) -> Tuple[Logger, 'Queue[str]', QueueListener]:
    from .mp import ctx

    if level is None:
        level = logging.DEBUG

    log_queue = ctx.Queue()

    handler_file = RotatingFileHandler(
        str(chain_config.logfile_path),
        maxBytes=(10000000 * LOG_MAX_MB),
        backupCount=LOG_BACKUP_COUNT
    )

    handler_file.setLevel(level)
    handler_file.setFormatter(formatter)

    logger.addHandler(handler_file)

    listener = QueueListener(
        log_queue,
        handler_stream,
        handler_file,
        respect_handler_level=True,
    )

    return logger, log_queue, listener


def setup_queue_logging(log_queue: Queue, level: int, log_levels = None) -> None:
    queue_handler = QueueHandler(log_queue)
    queue_handler.setLevel(level)

    logger = logging.getLogger()
    logger.addHandler(queue_handler)
    #logger.setLevel(level)
    # These loggers generates too much DEBUG noise, drowning out the important things, so force
    # the INFO level for it until https://github.com/ethereum/py-evm/issues/806 is fixed.
    # logging.getLogger('hp2p.peer.Peer').setLevel(logging.INFO)
    # logging.getLogger('hp2p.kademlia').setLevel(logging.INFO)
    # logging.getLogger('hp2p.discovery').setLevel(logging.INFO)
    if log_levels is not None:
        setup_log_levels(log_levels=log_levels)

    #logging.getLogger('hp2p.UPnPService').setLevel(logging.INFO)

    logger.debug('Logging initialized: PID=%s', os.getpid())


def with_queued_logging(fn: Callable) -> Callable:
    @functools.wraps(fn)
    def inner(*args, **kwargs):
        try:
            log_queue = kwargs['log_queue']
        except KeyError:
            raise KeyError("The `log_queue` argument is required when calling `{0}`".format(
                fn.__name__,
            ))
        else:
            log_level = kwargs.get('log_level', logging.INFO)
            log_levels = kwargs.get('log_levels', None)
            setup_queue_logging(log_queue, level=log_level, log_levels = log_levels)

            inner_kwargs = dissoc(kwargs, 'log_queue', 'log_level', 'log_levels')

            return fn(*args, **inner_kwargs)
    return inner

# class Whitelist(logging.Filter):
#     def __init__(self, *whitelist):
#         self.whitelist = [logging.Filter(name) for name in whitelist]
#
#     def filter(self, record):
#         return any(f.filter(record) for f in self.whitelist)

# handler_stream.addFilter(Whitelist(*filter_list))