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

import os
import sys
from typing import (
    Any,
    cast,
    Dict,
    Tuple,
    TYPE_CHECKING,
    Callable,
)

from cytoolz import dissoc

from hvm.tools.logging import (
    TraceLogger,
)

from helios.config import (
    ChainConfig,
)

if TYPE_CHECKING:
    from multiprocessing import Queue  # noqa: F401

LOG_BACKUP_COUNT = 10
LOG_MAX_MB = 5


class HeliosLogFormatter(logging.Formatter):

    def __init__(self, fmt: str, datefmt: str) -> None:
        super().__init__(fmt, datefmt)

    def format(self, record: logging.LogRecord) -> str:
        record.shortname = record.name.split('.')[-1]  # type: ignore
        return super().format(record)


class HasTraceLogger:
    _logger: TraceLogger = None

    @property
    def logger(self) -> TraceLogger:
        if self._logger is None:
            self._logger = cast(
                TraceLogger,
                logging.getLogger(self.__module__ + '.' + self.__class__.__name__)
            )
        return self._logger


def setup_log_levels(log_levels: Dict[str, int]) -> None:
    for name, level in log_levels.items():
        logger = logging.getLogger(name)
        logger.setLevel(level)

def disable_logging(logger: logging.Logger = None, name: str = None) -> None:
    if logger is not None:
        logger = logger
    elif name is not None:
        logger = logging.getLogger(name)
    else:
        logger = logging.getLogger('helios')
    logger.manager.disable = 50

def enable_logging(logger: logging.Logger = None, name: str = None) -> None:
    if logger is not None:
        logger = logger
    elif name is not None:
        logger = logging.getLogger(name)
    else:
        logger = logging.getLogger('helios')
    logger.manager.disable = 0

def setup_helios_stderr_logging(level: int=None) -> Tuple[Logger, Formatter, StreamHandler]:
    if level is None:
        level = logging.DEBUG
    logger = logging.getLogger('helios')
    logger.setLevel(logging.DEBUG)

    handler_stream = logging.StreamHandler(sys.stderr)
    handler_stream.setLevel(level)

    # TODO: allow configuring `detailed` logging
    formatter = HeliosLogFormatter(
        #fmt='%(levelname)8s  %(asctime)s  %(shortname)20s  %(message)s',
        fmt='%(levelname)8s  %(asctime)s  %(name)20s  %(message)s',
        datefmt='%m-%d %H:%M:%S'
    )

    handler_stream.setFormatter(formatter)

    logger.addHandler(handler_stream)

    logger.debug('Logging initialized: PID=%s', os.getpid())

    return logger, formatter, handler_stream


def setup_helios_file_and_queue_logging(
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


def setup_queue_logging(log_queue: 'Queue[str]', level: int, log_levels = None) -> None:
    queue_handler = QueueHandler(log_queue)
    queue_handler.setLevel(level)

    logger = cast(TraceLogger, logging.getLogger())
    logger.addHandler(queue_handler)
    logger.setLevel(level)

    if log_levels is not None:
        setup_log_levels(log_levels=log_levels)

    logger.debug('Logging initialized: PID=%s', os.getpid())


def with_queued_logging(fn: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(fn)
    def inner(*args: Any, **kwargs: Any) -> Any:
        try:
            log_queue = kwargs['log_queue']
        except KeyError:
            raise KeyError("The `log_queue` argument is required when calling `{0}`".format(
                fn.__name__,
            ))
        else:
            level = kwargs.get('log_level', logging.INFO)
            log_levels = kwargs.get('log_levels', None)
            setup_queue_logging(log_queue, level, log_levels)

            inner_kwargs = dissoc(kwargs, 'log_queue', 'log_level', 'log_levels')

            return fn(*args, **inner_kwargs)
    return inner


def _set_environ_if_missing(name: str, val: str) -> None:
    """
    Set the environment variable so that other processes get the changed value.
    """
    if os.environ.get(name, '') == '':
        os.environ[name] = val


def enable_warnings_by_default(python_warnings = True) -> None:
    """
    This turns on some python and asyncio warnings, unless
    the related environment variables are already set.
    """
    if python_warnings:
        _set_environ_if_missing('PYTHONWARNINGS', 'default')
    # PYTHONASYNCIODEBUG is not turned on by default because it slows down sync a *lot*
    logging.getLogger('asyncio').setLevel(logging.DEBUG)
