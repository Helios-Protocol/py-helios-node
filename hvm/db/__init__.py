# import os
# from typing import (
#     Any,
#     Type
# )
#
# from hvm.utils.module_loading import (
#     import_string,
# )
# from hvm.db.backends.base import (
#     BaseDB
# )
#
# DEFAULT_DB_BACKEND = 'hvm.db.backends.memory.MemoryDB'
#
#
# def get_db_backend_class(import_path: str = None) -> Type[BaseDB]:
#     if import_path is None:
#         import_path = os.environ.get(
#             'CHAIN_DB_BACKEND_CLASS',
#             DEFAULT_DB_BACKEND,
#         )
#     return import_string(import_path)
#
#
# def get_db_backend(import_path: str = None, **init_kwargs: Any) -> BaseDB:
#     backend_class = get_db_backend_class(import_path)
#     return backend_class(**init_kwargs)


import os
from typing import (
    Any,
    Type
)

from hvm.utils.module_loading import (
    import_string,
)
from hvm.db.backends.base import (
    BaseAtomicDB,
)

DEFAULT_DB_BACKEND = 'hls.db.atomic.AtomicDB'


def get_db_backend_class(import_path: str = None) -> Type[BaseAtomicDB]:
    if import_path is None:
        import_path = os.environ.get(
            'CHAIN_DB_BACKEND_CLASS',
            DEFAULT_DB_BACKEND,
        )
    return import_string(import_path)


def get_db_backend(import_path: str = None, **init_kwargs: Any) -> BaseAtomicDB:
    backend_class = get_db_backend_class(import_path)
    return backend_class(**init_kwargs)

