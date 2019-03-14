import asyncio
import contextlib
import cProfile
import functools
import linecache
import os
import tracemalloc
import logging

from typing import (
    Any,
    Callable,
    Iterator,
)


def get_top_memory_usage(snapshot, key_type='lineno', limit=3, logger = None):
    snapshot = snapshot.filter_traces((
        tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
        tracemalloc.Filter(False, "<unknown>"),
    ))
    top_stats = snapshot.statistics(key_type)

    out = []
    out.append("Top %s lines" % limit)
    for index, stat in enumerate(top_stats[:limit], 1):
        frame = stat.traceback[0]
        # replace "/path/to/module/file.py" with "module/file.py"
        filename = os.sep.join(frame.filename.split(os.sep)[-2:])
        out.append("#%s: %s:%s: %.1f KiB"
              % (index, filename, frame.lineno, stat.size / 1024))
        line = linecache.getline(frame.filename, frame.lineno).strip()
        if line:
            out.append('    %s' % line)

    other = top_stats[limit:]
    if other:
        size = sum(stat.size for stat in other)
        out.append("%s other: %.1f KiB" % (len(other), size / 1024))
    total = sum(stat.size for stat in top_stats)
    out.append("Total allocated size: %.1f KiB" % (total / 1024))

    if logger is not None:
        for line in out:
            logger.debug("{}".format(line))
    return out


async def coro_periodically_report_memory_stats(cancel_token, report_interval, memory_logger) -> None:
    import tracemalloc
    tracemalloc.start()
    while not cancel_token.triggered:
        memory_logger.debug("Starting memory usage report loop")
        snapshot = tracemalloc.take_snapshot()
        get_top_memory_usage(snapshot, limit=30, logger=memory_logger)
        await asyncio.sleep(report_interval)

def sync_periodically_report_memory_stats(report_interval, memory_logger) -> None:
    import tracemalloc
    import time
    tracemalloc.start()
    while True:
        memory_logger.debug("Starting memory usage report loop")
        snapshot = tracemalloc.take_snapshot()
        get_top_memory_usage(snapshot, limit=30, logger=memory_logger)
        time.sleep(report_interval)

@contextlib.contextmanager
def profiler(filename: str) -> Iterator[None]:
    pr = cProfile.Profile()
    pr.enable()
    try:
        yield
    finally:
        pr.disable()
        pr.dump_stats(filename)


def setup_cprofiler(filename: str) -> Callable[..., Any]:
    def outer(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def inner(*args: Any, **kwargs: Any) -> None:
            should_profile = kwargs.pop('profile', False)
            if should_profile:
                with profiler(filename):
                    return fn(*args, **kwargs)
            else:
                return fn(*args, **kwargs)
        return inner
    return outer
