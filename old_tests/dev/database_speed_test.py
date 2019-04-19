from hvm.db.backends.level import LevelDB
from hvm.db.backends.memory import MemoryDB

import time
from pathlib import Path
from typing import Any
import pickle
from helios.utils.profiling import setup_cprofiler
import pyssdb









test_directory = Path('test')

def speed_test(db):


    #level db write speed
    start_time = time.time()
    for i in range(200):
        #db[bytes(i)] = b'test'
        db[bytes([i])] = b'testfgsdgsdfgdsfgdsfg'+bytes(i)

    end_time = time.time()
    print('LevelDB write took leveldb {} seconds'.format(end_time-start_time))

    #leveldb read speed
    start_time = time.time()
    for i in range(200):
        #db[bytes(i)] = b'test'
        test = db[bytes([i])]

    end_time = time.time()
    print('LevelDB read took leveldb {} seconds'.format(end_time-start_time))


def speed_test_ssdb():
    db = pyssdb.Client()

    start_time = time.time()
    for i in range(200):
        #db[bytes(i)] = b'test'
        db.set(bytes([i]), b'testfgsdgsdfgdsfgdsfg'+bytes(i))

    end_time = time.time()
    print('ssdb write took leveldb {} seconds'.format(end_time-start_time))

    #leveldb read speed
    start_time = time.time()
    for i in range(200):
        #db[bytes(i)] = b'test'
        test = db.get(bytes([i]))

    end_time = time.time()
    print('ssdb read took leveldb {} seconds'.format(end_time-start_time))




#
# Multiple processes
#

from multiprocessing.managers import (  # type: ignore
    BaseManager,
    BaseProxy,
)

from helios.chains import TracebackRecorder

from helios.db.base import DBProxy
from helios.utils.mp import (
    ctx,
)
import signal

from helios.utils.ipc import (
    wait_for_ipc,
)
from helios.utils.db_proxy import create_db_manager

db_ipc_path = test_directory / "db_ipc"

def get_chaindb_manager(base_db):
    class DBManager(BaseManager):
        pass

    # Typeshed definitions for multiprocessing.managers is incomplete, so ignore them for now:
    # https://github.com/python/typeshed/blob/85a788dbcaa5e9e9a62e55f15d44530cd28ba830/stdlib/3/multiprocessing/managers.pyi#L3
    DBManager.register(  # type: ignore
        'get_db', callable=lambda: TracebackRecorder(base_db), proxytype=DBProxy)


    manager = DBManager(address=str(db_ipc_path))  # type: ignore
    return manager

def run_database_process(base_db) -> None:


    manager = get_chaindb_manager(base_db)
    server = manager.get_server()  # type: ignore

    def _sigint_handler(*args: Any) -> None:
        server.stop_event.set()

    signal.signal(signal.SIGINT, _sigint_handler)
    try:
        server.serve_forever()
    except SystemExit:
        server.stop_event.set()
        raise


@setup_cprofiler('main_test')
def main():

    base_db = LevelDB(test_directory / "leveldb_multiprocess3")
    base_db = MemoryDB()
    database_server_process = ctx.Process(
        target=run_database_process,
        args=(base_db,),
    )
    print('1')
    # start the processes
    database_server_process.start()
    print('2')
    try:
        print('3')
        wait_for_ipc(db_ipc_path)
    except TimeoutError as e:
        print("Timeout when starting db process")

    db_manager = create_db_manager(db_ipc_path)
    db_manager.connect()

    mp_db = db_manager.get_db()

    db = LevelDB(test_directory / "leveldb")
    speed_test(db)
    speed_test(mp_db)


    database_server_process.join()


if __name__ == "__main__":
    __spec__ = 'None'
    main(profile=True)