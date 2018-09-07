import contextlib
import cProfile
import functools
from typing import Callable


@contextlib.contextmanager
def profiler(filename):
    print('TESTEST1')
    pr = cProfile.Profile()
    pr.enable()
    try:
        yield
    finally:
        pr.disable()
        print('TESTEST2')
        pr.dump_stats(filename)


def setup_cprofiler(filename):
    def outer(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def inner(*args, **kwargs):
            should_profile = kwargs.pop('profile', False)
            if should_profile:
                with profiler(filename):
                    return fn(*args, **kwargs)
            else:
                return fn(*args, **kwargs)
        return inner
    return outer
