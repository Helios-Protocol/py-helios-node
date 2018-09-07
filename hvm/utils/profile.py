 
import cProfile, pstats, io

def profile(sortby='cumulative'):
    def profile_inner(fnc):
        """A decorator that uses cProfile to profile a function"""

        def inner(*args, **kwargs):
            pr = cProfile.Profile()
            pr.enable()
            retval = fnc(*args, **kwargs)
            pr.disable()
            s = io.StringIO()
            ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
            ps.print_stats()
            print(s.getvalue())
            return retval

        return inner
    return profile_inner